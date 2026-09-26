/// Threat classes reported by the engine.
enum ThreatType {
  root,
  emulator,
  debugger,
  hooking,
  tamper,
  untrustedInstaller,
  devOptions,
  adbEnabled,
  noScreenLock,

  /// An enabled accessibility service that can read the screen or act, and is not a known assistive tool.
  accessibilityAbuse,

  /// A touch on a sensitive screen arrived through another app's overlay (tapjacking).
  overlay,

  /// A screenshot was taken (Android 14+).
  screenCapture,

  /// The app window is being recorded (Android 15+).
  screenRecording,

  /// The screen is mirrored to a presentation display (Cast, Miracast, external screen).
  screenMirroring,

  /// A remote-access app (AnyDesk, TeamViewer QuickSupport, ...) is installed.
  remoteAccessApp,

  /// A phone or VoIP call is in progress.
  activeCall,

  /// A detector could not run (it threw, or the native core is missing). Protection is degraded.
  detectorFailure;

  static ThreatType? fromName(String name) {
    for (final value in values) {
      if (value.name == name) return value;
    }
    return null;
  }
}

/// Local reactions. The v1 engine is headless and offline, so every reaction runs on the device.
enum Reaction {
  /// Record the threat in the on-device event log and emit an event.
  report,

  /// Ask the app to show a warning (the event carries the flag; the app renders it).
  warnUser,

  /// Make [Rasp.guard] deny flows listed in [RaspConfig.sensitiveFlows].
  blockSensitive,

  /// Set FLAG_SECURE on the app window while the threat is active.
  secureScreen,

  /// Close the app a few seconds after the event is emitted.
  closeApp;

  static Reaction? fromName(String name) {
    for (final value in values) {
      if (value.name == name) return value;
    }
    return null;
  }
}

enum RiskLevel { none, low, medium, high }

class RaspConfig {
  const RaspConfig({
    this.expectedPackageName,
    this.accessibilityAllowlist = const [],
    this.expectedSigningCertSha256 = const [],
    this.allowedInstallers = const [],
    this.checkIntervalSeconds = 15,
    this.sensitiveFlows = const {},
    this.policy = const {},
    this.devMode = false,
  });

  /// Package name the app must run under. Null skips the check.
  final String? expectedPackageName;

  /// Extra accessibility-service packages to trust, on top of the built-in assistive tools (TalkBack, Voice Access...).
  final List<String> accessibilityAllowlist;

  /// SHA-256 digests of the release signing certificate(s), hex with or without colons. Empty skips the check.
  final List<String> expectedSigningCertSha256;

  /// Installer package names considered trusted, e.g. `com.android.vending`. Empty skips the check.
  final List<String> allowedInstallers;

  /// Delay between background scans. Minimum 5 seconds.
  final int checkIntervalSeconds;

  /// Flow names that [Rasp.guard] may deny.
  final Set<String> sensitiveFlows;

  /// Overrides for the default reactions per threat.
  final Map<ThreatType, Set<Reaction>> policy;

  /// Report only, never react. Use for debug builds.
  final bool devMode;

  Map<String, Object?> toMap() => {
        'expectedPackageName': expectedPackageName,
        'accessibilityAllowlist': accessibilityAllowlist,
        'expectedSigningCertSha256': expectedSigningCertSha256,
        'allowedInstallers': allowedInstallers,
        'checkIntervalSeconds': checkIntervalSeconds,
        'sensitiveFlows': sensitiveFlows.toList(),
        'policy': {
          for (final entry in policy.entries) entry.key.name: entry.value.map((r) => r.name).toList(),
        },
        'devMode': devMode,
      };
}

class RaspSignal {
  const RaspSignal({
    required this.threat,
    required this.detector,
    required this.confidence,
    required this.evidence,
  });

  factory RaspSignal.fromMap(Map<Object?, Object?> map) => RaspSignal(
        threat: ThreatType.fromName(map['threat']! as String)!,
        detector: map['detector']! as String,
        confidence: (map['confidence']! as num).toInt(),
        evidence: map['evidence']! as String,
      );

  final ThreatType threat;
  final String detector;
  final int confidence;
  final String evidence;
}

class SecurityReport {
  const SecurityReport({
    required this.riskLevel,
    required this.threats,
    required this.signals,
    required this.timestamp,
  });

  factory SecurityReport.fromMap(Map<Object?, Object?> map) => SecurityReport(
        riskLevel: RiskLevel.values.byName(map['riskLevel']! as String),
        threats: {
          for (final threat in (map['threats']! as List).cast<Map<Object?, Object?>>())
            ThreatType.fromName(threat['type']! as String)!: _reactions(threat['reactions']),
        },
        signals: [
          for (final signal in (map['signals']! as List).cast<Map<Object?, Object?>>()) RaspSignal.fromMap(signal),
        ],
        timestamp: DateTime.fromMillisecondsSinceEpoch((map['timestamp']! as num).toInt()),
      );

  final RiskLevel riskLevel;

  /// Active threats and the reactions the policy applies to each.
  final Map<ThreatType, Set<Reaction>> threats;
  final List<RaspSignal> signals;
  final DateTime timestamp;

  bool get isClean => threats.isEmpty;
}

class GuardResult {
  const GuardResult({
    required this.flow,
    required this.allowed,
    required this.blockingThreats,
    this.warnings = const [],
    required this.report,
  });

  factory GuardResult.fromMap(Map<Object?, Object?> map) => GuardResult(
        flow: map['flow']! as String,
        allowed: map['allowed']! as bool,
        blockingThreats: [
          for (final name in (map['blockingThreats']! as List).cast<String>()) ThreatType.fromName(name)!,
        ],
        warnings: [
          for (final name in ((map['warnings'] as List?) ?? const []).cast<String>()) ?ThreatType.fromName(name),
        ],
        report: SecurityReport.fromMap(map['report']! as Map<Object?, Object?>),
      );

  final String flow;
  final bool allowed;
  final List<ThreatType> blockingThreats;

  /// Threats the user should be told about before continuing, e.g. a call in progress during a transfer.
  final List<ThreatType> warnings;
  final SecurityReport report;
}

/// Result of binding the install to a hardware-backed key. Send all of it to the bank's server.
class DeviceBindingResult {
  const DeviceBindingResult({
    required this.keyAlias,
    required this.strongBox,
    required this.userAuthRequired,
    required this.publicKey,
    required this.certificateChain,
  });

  factory DeviceBindingResult.fromMap(Map<Object?, Object?> map) => DeviceBindingResult(
        keyAlias: map['keyAlias']! as String,
        strongBox: map['strongBox']! as bool,
        userAuthRequired: (map['userAuthRequired'] as bool?) ?? false,
        publicKey: map['publicKey']! as String,
        certificateChain: (map['certificateChain']! as List).cast<String>(),
      );

  final String keyAlias;

  /// Whether the key lives in a StrongBox secure element rather than the TEE.
  final bool strongBox;

  /// Whether every signature needs the user's biometric or device credential.
  final bool userAuthRequired;

  /// SubjectPublicKeyInfo, DER, base64.
  final String publicKey;

  /// Key Attestation chain, leaf first, DER, base64.
  final List<String> certificateChain;
}

/// A transaction signed by the bound key, with the RASP verdict inside the signed text.
class SignedTransaction {
  const SignedTransaction({required this.signedData, required this.signature, required this.guard});

  factory SignedTransaction.fromMap(Map<Object?, Object?> map) => SignedTransaction(
        signedData: map['signedData']! as String,
        signature: map['signature']! as String,
        guard: GuardResult.fromMap(map['guard']! as Map<Object?, Object?>),
      );

  /// Canonical text that was signed (format `rasp-tx-1`).
  final String signedData;

  /// ECDSA P-256 / SHA-256 signature over [signedData], DER, base64.
  final String signature;

  /// The local verdict for the flow, computed in the same scan as the signed report.
  final GuardResult guard;
}

/// Emitted when threats become active that were not active in the previous scan.
class ThreatEvent {
  const ThreatEvent({
    required this.timestamp,
    required this.riskLevel,
    required this.newThreats,
    required this.reactions,
    required this.signals,
  });

  factory ThreatEvent.fromMap(Map<Object?, Object?> map) => ThreatEvent(
        timestamp: DateTime.fromMillisecondsSinceEpoch((map['timestamp']! as num).toInt()),
        riskLevel: RiskLevel.values.byName(map['riskLevel']! as String),
        newThreats: [
          for (final name in (map['newThreats']! as List).cast<String>()) ThreatType.fromName(name)!,
        ],
        reactions: _reactions(map['reactions']),
        signals: [
          for (final signal in (map['signals']! as List).cast<Map<Object?, Object?>>()) RaspSignal.fromMap(signal),
        ],
      );

  final DateTime timestamp;
  final RiskLevel riskLevel;
  final List<ThreatType> newThreats;
  final Set<Reaction> reactions;
  final List<RaspSignal> signals;

  bool get shouldWarnUser => reactions.contains(Reaction.warnUser) || reactions.contains(Reaction.closeApp);
  bool get willCloseApp => reactions.contains(Reaction.closeApp);
}

Set<Reaction> _reactions(Object? names) => {
      for (final name in (names! as List).cast<String>()) ?Reaction.fromName(name),
    };
