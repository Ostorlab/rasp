"""A fake app for the strategy tests: the test gives the classes and their links directly."""

import collections.abc

from dexsplit import partition
from dexsplit import strategy


class FakeApp:
    """A `strategy.App` with no app behind it: the test gives the classes and their links.

    Each given edge is one link, counted with weight 1 whatever its kind. `asked_weights` records
    the weights of every `links` call.
    """

    def __init__(
        self,
        descriptors: collections.abc.Sequence[str],
        sources: collections.abc.Sequence[int] | None = None,
        edges: collections.abc.Iterable[tuple[int, int]] = (),
    ) -> None:
        self._descriptors = descriptors
        self._sources = [0] * len(descriptors) if sources is None else sources
        self._edges = list(edges)
        self.asked_weights: list[dict[strategy.LinkKind, int]] = []

    @property
    def descriptors(self) -> collections.abc.Sequence[str]:
        return self._descriptors

    def source_dex(self, class_id: int) -> int:
        return self._sources[class_id]

    def links(
        self,
        class_ids: collections.abc.Sequence[int],
        weights: collections.abc.Mapping[strategy.LinkKind, int],
    ) -> partition.AffinityGraph:
        self.asked_weights.append(dict(weights))
        members = set(class_ids)
        graph = partition.AffinityGraph(len(self._descriptors))
        for first, second in self._edges:
            if first in members and second in members:
                graph.add_edge(first, second)
        return graph


def make_classes(
    descriptors: collections.abc.Sequence[str],
    sources: collections.abc.Sequence[int] | None = None,
    edges: collections.abc.Iterable[tuple[int, int]] = (),
) -> strategy.Classes:
    return strategy.Classes(
        list(range(len(descriptors))), FakeApp(descriptors, sources, edges)
    )
