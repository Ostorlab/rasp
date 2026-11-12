"""Direct native trust boundaries, using the real compiled reader."""

import array
import hashlib
import pathlib
import struct
import zlib

import pytest

from dexsplit import _dex

_SAMPLE = pathlib.Path(__file__).parent / "fixtures" / "sample.dex"


@pytest.mark.parametrize(("field", "value"), [(8, 0), (32, 1), (36, 0), (104, 0)])
def testRead_whenHeaderIsInconsistent_rejects(field: int, value: int) -> None:
    data = bytearray(_SAMPLE.read_bytes())
    struct.pack_into("<I", data, field, value)
    if field != 8:
        data[12:32] = hashlib.sha1(data[32:]).digest()
        struct.pack_into("<I", data, 8, zlib.adler32(data[12:]))
    with pytest.raises(ValueError, match=r"(?i)(dex|checksum|header|size)"):
        _dex.Model.read(bytes(data))


def testRead_whenNonByteBuffer_rejectsBeforeInterpretingMemory() -> None:
    data = array.array("I")
    data.frombytes(_SAMPLE.read_bytes())
    with pytest.raises(ValueError, match=r"contiguous.*byte"):
        _dex.Model.read(memoryview(data))


def testRead_whenBufferIsStrided_rejectsBeforeReading() -> None:
    with pytest.raises(ValueError, match="contiguous"):
        _dex.Model.read(memoryview(_SAMPLE.read_bytes())[::2])


def testRequest_whenNested_doesNotResetAllowance() -> None:
    with _dex.Request(work=4) as outer:
        outer.charge(work=3)
        with _dex.Request() as inner, pytest.raises(_dex.BudgetError):
            inner.charge(work=2)
        assert outer.work == 3


def testRequest_whenApprovedDefaultIsExactlyConsumed_nestedScopeCannotReset() -> None:
    with _dex.Request() as outer:
        outer.charge(work=64_000_000, storage=1_610_612_736)
        with _dex.Request() as inner:
            assert inner.work == 64_000_000
            assert inner.storage == 1_610_612_736
            with pytest.raises(_dex.BudgetError):
                inner.charge(work=1)
            with pytest.raises(_dex.BudgetError):
                inner.charge(storage=1)
        assert outer.work == 64_000_000
        assert outer.storage == 1_610_612_736


@pytest.mark.parametrize(
    ("limit", "value"),
    [("work", 64_000_001), ("work", 67_108_864), ("storage", 1_610_612_737)],
)
def testRequest_whenAboveExactApprovedDefault_refuses(limit: str, value: int) -> None:
    arguments = {limit: value}
    with pytest.raises(ValueError, match="exceed finite defaults"):
        _dex.Request(**arguments)


def testRead_whenAllocationBudgetIncreases_inputByteCapsStayUnchanged() -> None:
    payload = bytes(64 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="64 MiB"):
        _dex.Model.read(payload)
    exact_input_limit = payload[:-1]
    with pytest.raises(ValueError, match="aggregate DEX input limit exceeded"):
        _dex.AnalysisContext.from_dex_buffers([exact_input_limit] * 5)


@pytest.mark.parametrize("limit", ["work", "storage"])
def testRead_whenNativeAllowanceIsExhausted_failsBeforeGrowth(limit: str) -> None:
    request = _dex.Request(work=0) if limit == "work" else _dex.Request(storage=0)
    with request, pytest.raises(_dex.BudgetError):
        _dex.Model.read(_SAMPLE.read_bytes())
    assert len(_dex.Model.read(_SAMPLE.read_bytes()).class_descriptors) == 12


def testWrite_whenOriginalRequestScopeExited_retainsCumulativeAllowance() -> None:
    allowance = 4 * 1024 * 1024
    with _dex.Request(storage=allowance) as request:
        model = _dex.Model.read(_SAMPLE.read_bytes())
    spent = request.storage
    model.write()
    assert request.storage > spent
    exhausted = False
    for _ in range(256):
        try:
            model.write()
        except _dex.BudgetError:
            exhausted = True
            break
    assert exhausted is True
    assert request.storage <= allowance
    assert request.backing <= 512 * 1024 * 1024
    with pytest.raises(_dex.BudgetError):
        model.write()


def testCopy_whenOriginalScopeExited_preservesSourceAllowance() -> None:
    with _dex.Request() as request:
        source = _dex.Model.read(_SAMPLE.read_bytes())
    spent = request.storage
    destination = _dex.Model(35)
    destination.copy_class(source, "Lcom/android/insecurebankv2/BuildConfig;")
    destination.write()
    assert request.storage > spent


def testAnalysis_whenOriginalScopeExited_handlesRetainBudgetAndOwnedBuffers() -> None:
    with _dex.Request() as request:
        context = _dex.AnalysisContext.from_dex_buffers([_SAMPLE.read_bytes()])
    spent = request.storage
    classes = context.classes
    assert len(classes) == 12
    assert request.storage > spent
    del context
    assert classes[0].name.startswith("L")


@pytest.mark.parametrize("version", [35, 37, 38, 39, 40])
def testReadWrite_whenRealVersionFeature_preservesBytesAndAnalysis(
    version: int,
) -> None:
    data = (_SAMPLE.parent / "versions" / f"feature-{version:03}.dex").read_bytes()
    with _dex.Request():
        model = _dex.Model.read(data)
        assert model.write() == data
        context = _dex.AnalysisContext.from_models([model])
        assert len(context.classes) == 1
        assert context.classes[0].name == model.class_descriptors[0]
