"""Split the classes of an app into grouped DEX files, in memory.

The classes are sorted into named sets (see `dexsplit.class_sets`), and the strategy of each set
groups its classes (see `dexsplit.strategy`). Each group is written as one DEX file, or as several
when it goes over a 64K limit of the DEX format. Every class lands in exactly one DEX file, and two
sets never share a file.

The input is the app's `classes*.dex` entries as bytes, keyed by name. The output is the grouped DEX
files as bytes, with the classes each one defines, so nothing is read from or written to disk.
"""

import collections.abc
import dataclasses
import logging
import re

import dexsplit
from dexsplit import _dex
from dexsplit import class_sets
from dexsplit import partition
from dexsplit import strategy

_LOGGER = logging.getLogger(__name__)

# Older DEX files are written as 035, the lowest DEX version.
_MIN_DEX_VERSION = 35

# A top-level DEX entry name: classes.dex, then classes2.dex, classes3.dex, ...
_DEX_ENTRY = re.compile(r"classes([0-9]*)\.dex")
_MAX_DEX_ENTRY_NUMBER = 0xFFFFFFFF

# How many classes an error message about a strategy's groups names.
_EXAMPLES = 3


class SplitError(dexsplit.Error):
    """Raised when the DEX entries cannot be read or the classes cannot be regrouped."""


@dataclasses.dataclass(frozen=True)
class OutputDex:
    """One grouped DEX file the split produced.

    Attributes:
        set_name: The name of the set this file belongs to.
        classes: The descriptors of the classes in the file, in write order.
        data: The DEX file bytes.
    """

    set_name: str
    classes: tuple[str, ...]
    data: bytes


@dataclasses.dataclass(frozen=True)
class Result:
    """What a split produced.

    Attributes:
        files: The grouped DEX files, set by set, each set's files in write order.
    """

    files: tuple[OutputDex, ...]


def split(
    dex_entries: collections.abc.Mapping[str, bytes],
    sets: collections.abc.Sequence[class_sets.ClassSet],
    assignments: collections.abc.Sequence[class_sets.Assignment],
) -> Result:
    """Split the classes of an app into grouped DEX files.

    Args:
        dex_entries: The app's `classes*.dex` entries, keyed by their bare name. Read in multidex
            order (`classes.dex`, `classes2.dex`, ...).
        sets: The sets to sort the classes into. Their DEX files come out in this order.
        assignments: Which classes go to which set, tried in order (see `dexsplit.class_sets.assign`).

    Returns:
        The grouped DEX files, with the descriptors of the classes each one defines.

    Raises:
        SplitError: A DEX entry is missing or cannot be read, or a group cannot be written.
        dexsplit.class_sets.AssignmentError: The classes cannot be sorted into the sets.
        dexsplit.strategy.StrategyError: A strategy returns groups that break the rules.
    """
    ordered = _ordered_names(dex_entries)
    if len(ordered) == 0:
        raise SplitError("no classes*.dex entries to split")
    buffers = [dex_entries[name] for name in ordered]
    classes = _read_classes(buffers)
    members = class_sets.assign(classes.descriptors, sets, assignments)
    app = _App(buffers, classes)
    plans = [_plan(class_set, members[class_set.name], app) for class_set in sets]
    return Result(files=tuple(_build_outputs(classes, sets, plans)))


@dataclasses.dataclass(frozen=True)
class _Classes:
    """The classes of the app's DEX files. Class ids count from 0, in multidex order.

    Attributes:
        models: One editable model per DEX entry, in multidex order.
        descriptors: The descriptor of each class, indexed by class id.
        sources: The index in `models` of the DEX file each class comes from.
        index_of: The class id of each descriptor.
        version: The DEX version to write: the highest version read, and at least 035.
    """

    models: list[_dex.Model]
    descriptors: list[str]
    sources: list[int]
    index_of: dict[str, int]
    version: int


def _ordered_names(dex_entries: collections.abc.Mapping[str, bytes]) -> list[str]:
    """The `classes*.dex` entry names, in multidex order; ties on the number are broken by name."""
    numbers: dict[str, int] = {}
    for name in dex_entries:
        number = _multidex_number(name)
        if number is not None:
            numbers[name] = number
    return sorted(numbers, key=lambda name: (numbers[name], name))


def _multidex_number(name: str) -> int | None:
    """The multidex order of a DEX entry: 1 for classes.dex, N for classesN.dex (N >= 2)."""
    match = _DEX_ENTRY.fullmatch(name)
    if match is None:
        return None
    digits = match.group(1)
    if digits == "":
        return 1
    number = int(digits)
    if number < 2 or number > _MAX_DEX_ENTRY_NUMBER:
        return None
    return number


def _read_classes(buffers: collections.abc.Sequence[bytes]) -> _Classes:
    """Read the classes of every DEX entry, in multidex order, keeping each class once.

    A class defined in more than one DEX file is kept once: the first copy in multidex order, which
    is the one Android loads. Keeping both would put one class in two output files.
    """
    models: list[_dex.Model] = []
    descriptors: list[str] = []
    sources: list[int] = []
    index_of: dict[str, int] = {}
    for source, data in enumerate(buffers):
        model = _read_model(data, source)
        models.append(model)
        for descriptor in model.class_descriptors:
            if descriptor in index_of:
                continue
            index_of[descriptor] = len(descriptors)
            descriptors.append(descriptor)
            sources.append(source)
    version = max(_MIN_DEX_VERSION, *(model.version for model in models))
    return _Classes(models, descriptors, sources, index_of, version)


def _read_model(data: bytes, source: int) -> _dex.Model:
    """Read one DEX entry into an editable model."""
    try:
        return _dex.Model.read(data)
    except ValueError as error:
        raise SplitError(f"cannot read classes entry {source}: {error}") from error


class _App:
    """What the splitter knows about the app, shared by every set (see `strategy.App`).

    The analysis of the app's code is made on first use, by the first set that needs it.
    """

    def __init__(
        self, buffers: collections.abc.Sequence[bytes], classes: _Classes
    ) -> None:
        self._buffers = buffers
        self._classes = classes
        self._context: _dex.AnalysisContext | None = None

    @property
    def descriptors(self) -> collections.abc.Sequence[str]:
        """The descriptor of every class of the app, by class id."""
        return self._classes.descriptors

    def source_dex(self, class_id: int) -> int:
        """The input DEX file a class comes from: 0 for `classes.dex`, 1 for `classes2.dex`, ..."""
        return self._classes.sources[class_id]

    def links(
        self,
        class_ids: collections.abc.Sequence[int],
        weights: collections.abc.Mapping[strategy.LinkKind, int],
    ) -> partition.AffinityGraph:
        """The links among the given classes, each link counted with the weight of its kind.

        Only the code of the given classes is read, so the cost follows the size of the set. A class
        defined in more than one DEX file is read once, from its first copy in multidex order.
        """
        members = set(class_ids)
        index_of = self._classes.index_of
        graph = partition.AffinityGraph(len(self._classes.descriptors))
        read: set[int] = set()
        for cls in self._analysis.classes:
            class_id = index_of.get(cls.name)
            if class_id is None or class_id not in members or class_id in read:
                continue
            read.add(class_id)
            for descriptor, weight in _weighted_links(cls, weights):
                other = index_of.get(descriptor)
                if other is not None and other in members:
                    graph.add_edge(class_id, other, weight)
        return graph

    @property
    def _analysis(self) -> _dex.AnalysisContext:
        """The analysis of the app's code, built on first use."""
        if self._context is None:
            self._context = _dex.AnalysisContext.from_dex_buffers(list(self._buffers))
        return self._context


def _weighted_links(
    cls: _dex.Class, weights: collections.abc.Mapping[strategy.LinkKind, int]
) -> collections.abc.Iterator[tuple[str, int]]:
    """The class descriptors a class is linked to, once per link, with the weight of the link.

    Those are its superclass, the interfaces it implements, the top-level class it is nested in
    (`LFoo$Bar;` is linked to `LFoo;`), and every class that one of its methods refers to: a called
    method, an accessed field, or a used type (`new`, a cast, `instanceof`, ...). Links of a kind
    that weighs 0 are skipped without reading them.
    """
    superclass = cls.superclass
    if superclass is not None and weights[strategy.LinkKind.SUPERCLASS] != 0:
        yield superclass.descriptor, weights[strategy.LinkKind.SUPERCLASS]
    if weights[strategy.LinkKind.INTERFACE] != 0:
        for interface in cls.interfaces:
            yield interface.descriptor, weights[strategy.LinkKind.INTERFACE]
    name = cls.name
    dollar = name.find("$")
    if dollar != -1 and weights[strategy.LinkKind.NESTING] != 0:
        yield name[:dollar] + ";", weights[strategy.LinkKind.NESTING]
    yield from _code_links(cls, weights)


def _code_links(
    cls: _dex.Class, weights: collections.abc.Mapping[strategy.LinkKind, int]
) -> collections.abc.Iterator[tuple[str, int]]:
    """The classes the methods of a class refer to, with the weight of each reference's kind."""
    call_weight = weights[strategy.LinkKind.CALL]
    field_weight = weights[strategy.LinkKind.FIELD]
    type_weight = weights[strategy.LinkKind.TYPE]
    if call_weight == 0 and field_weight == 0 and type_weight == 0:
        return
    for method in cls.methods:
        if call_weight != 0:
            for call in method.calls:
                yield call.target.class_descriptor, call_weight
        if field_weight != 0:
            for access in method.field_accesses:
                yield access.field.class_descriptor, field_weight
        if type_weight != 0:
            for use in method.type_uses:
                yield use.descriptor, type_weight


def _plan(
    class_set: class_sets.ClassSet,
    class_ids: collections.abc.Sequence[int],
    app: _App,
) -> list[strategy.Group]:
    """Ask the set's strategy for its groups, and check them."""
    groups = list(class_set.strategy.plan(strategy.Classes(class_ids, app)))
    _check_groups(class_set.name, groups, class_ids, app.descriptors)
    return groups


def _check_groups(
    set_name: str,
    groups: collections.abc.Sequence[strategy.Group],
    class_ids: collections.abc.Sequence[int],
    descriptors: collections.abc.Sequence[str],
) -> None:
    """Check that a strategy put every class of its set in exactly one non-empty block."""
    expected = set(class_ids)
    seen: set[int] = set()
    for group in groups:
        if len(group.blocks) == 0:
            raise strategy.StrategyError(
                f"set {set_name}: the strategy returned an empty group"
            )
        for block in group.blocks:
            if len(block.class_ids) == 0:
                raise strategy.StrategyError(
                    f"set {set_name}: the strategy returned an empty block"
                )
            for class_id in block.class_ids:
                if class_id not in expected:
                    raise strategy.StrategyError(
                        f"set {set_name}: the strategy returned class id {class_id}, which is "
                        "not in the set"
                    )
                if class_id in seen:
                    raise strategy.StrategyError(
                        f"set {set_name}: the strategy returned {descriptors[class_id]} twice"
                    )
                seen.add(class_id)
    if len(seen) < len(expected):
        missing = [
            descriptors[class_id] for class_id in class_ids if class_id not in seen
        ]
        raise strategy.StrategyError(
            f"set {set_name}: the strategy left out {len(missing)} classes, such as "
            f"{', '.join(missing[:_EXAMPLES])}"
        )


def _build_outputs(
    classes: _Classes,
    sets: collections.abc.Sequence[class_sets.ClassSet],
    plans: collections.abc.Sequence[collections.abc.Sequence[strategy.Group]],
) -> list[OutputDex]:
    """Encode the groups of every set as DEX files, set by set, in write order."""
    outputs: list[OutputDex] = []
    for class_set, groups in zip(sets, plans, strict=True):
        for group in groups:
            _write_group(outputs, class_set.name, group, classes)
    return outputs


def _write_group(
    outputs: list[OutputDex],
    set_name: str,
    group: strategy.Group,
    classes: _Classes,
) -> None:
    """Encode a group as one DEX file, or as several if it goes over a 64K limit.

    A group that goes over a limit is cut in two (see `_cut`), and each part is encoded again, the
    first part first.
    """
    pending = [list(group.blocks)]
    while len(pending) > 0:
        blocks = pending.pop()
        class_ids = [class_id for block in blocks for class_id in block.class_ids]
        data = _encode(classes, class_ids)
        if data is None:
            first, second = _cut(blocks)
            pending.append(second)
            pending.append(first)
        else:
            descriptors = tuple(classes.descriptors[class_id] for class_id in class_ids)
            outputs.append(OutputDex(set_name=set_name, classes=descriptors, data=data))


def _encode(
    classes: _Classes, class_ids: collections.abc.Sequence[int]
) -> bytes | None:
    """The classes as DEX bytes, or None if they go over a 64K limit and can be cut."""
    model = _dex.Model(classes.version)
    for class_id in class_ids:
        source = classes.models[classes.sources[class_id]]
        model.copy_class(source, classes.descriptors[class_id])
    try:
        return model.write()
    except _dex.PoolOverflowError as error:
        if len(class_ids) > 1:
            return None
        raise SplitError(f"write failed: {error}") from error
    except ValueError as error:
        raise SplitError(f"write failed: {error}") from error


def _cut(
    blocks: list[strategy.Block],
) -> tuple[list[strategy.Block], list[strategy.Block]]:
    """Cut blocks that go over a 64K limit in two.

    The cut falls at the block boundary nearest the middle (the first one on a tie). A single block
    is cut in its middle, with a warning that names it when it has a name.
    """
    half = sum(len(block.class_ids) for block in blocks) // 2
    if len(blocks) == 1:
        block = blocks[0]
        if block.name is not None:
            _LOGGER.warning(
                "%s goes over a 64K limit of the DEX format, so it is cut into two DEX files",
                block.name,
            )
        return (
            [strategy.Block(block.class_ids[:half], block.name)],
            [strategy.Block(block.class_ids[half:], block.name)],
        )
    boundaries: list[int] = []
    position = 0
    for block in blocks[:-1]:
        position += len(block.class_ids)
        boundaries.append(position)
    cut = min(range(len(boundaries)), key=lambda index: abs(boundaries[index] - half))
    return blocks[: cut + 1], blocks[cut + 1 :]
