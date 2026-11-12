import RaspRuntime

// Import every public vocabulary constant; values and signed CInt width remain stable.
let actionVocabulary: [Int32] = [
    kRaspLocalDeny,
    kRaspLocalReport,
    kRaspLocalAllow,
]
precondition(actionVocabulary == [0, 1, 2])
let statusVocabulary: [Int32] = [
    kRaspLocalOk,
    kRaspLocalInvalidArgument,
    kRaspLocalUnsupportedAbi,
    kRaspLocalNotReady,
    kRaspLocalBusy,
    kRaspLocalInvalidPolicy,
    kRaspLocalUnsupportedPolicy,
    kRaspLocalInternalError,
]
precondition(statusVocabulary == [0, 1, 2, 3, 4, 5, 6, 7])
let reasonVocabulary: [Int32] = [
    kRaspLocalNoSelection,
    kRaspLocalPolicyInvalid,
    kRaspLocalPolicyUnsupported,
    kRaspLocalHashMismatch,
    kRaspLocalOperationUnknown,
    kRaspLocalNoPublication,
    kRaspLocalCoverageUnavailable,
    kRaspLocalClockUnavailable,
    kRaspLocalStale,
    kRaspLocalSlowCycle,
    kRaspLocalRequiredUnavailable,
    kRaspLocalIndicatorPresent,
    kRaspLocalAllAbsent,
    kRaspLocalBindingMismatch,
    kRaspLocalContended,
    kRaspLocalBadArgument,
]
precondition(reasonVocabulary == [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])

// Owned Swift values and an actual adapted harmless operation; no private C++ object.
var receipts: [UInt32] = []
var request = RaspLocalGateRequestV1()
request.abi_version = 1
request.struct_size = UInt32(MemoryLayout<RaspLocalGateRequestV1>.size)
let operation = Array("append_demo_receipt".utf8) + [0]
let expectation = Array("093f2b8093e5c12d1d1b8f14f1fa945b87a4a03d15d891b55af861da06d4124e".utf8) + [0]
withUnsafeMutableBytes(of: &request.operation) { destination in
    destination.copyBytes(from: operation)
}
withUnsafeMutableBytes(of: &request.expected_policy_sha256) { destination in
    destination.copyBytes(from: expectation)
}
var decision = RaspLocalGateResultV1()
let status = rasp_local_policy_gate_v1(&request, UInt32(MemoryLayout<RaspLocalGateRequestV1>.size),
                                      &decision, UInt32(MemoryLayout<RaspLocalGateResultV1>.size))
if status == kRaspLocalOk && decision.action == UInt32(kRaspLocalAllow) {
    receipts.append(1)
}
var policyInfo = RaspLocalPolicyInfoV1()
_ = rasp_local_policy_info_v1(&policyInfo, UInt32(MemoryLayout<RaspLocalPolicyInfoV1>.size))
// A queued/resumed operation must call the gate again at its actual execution point.

// Imported uint32 fields retain their full positive domain in Swift.
let visiblePolicyVersion: UInt64 = UInt64(decision.policy_version)
var versionBoundary = RaspLocalPolicyInfoV1()
versionBoundary.policy_version = UInt32.max
precondition(UInt64(versionBoundary.policy_version) == 4294967295)
var decisionBoundary = RaspLocalGateResultV1()
decisionBoundary.policy_version = UInt32.max
precondition(UInt64(decisionBoundary.policy_version) == 4294967295)
