/// Offline runtime application self-protection for Flutter apps (Android).
library;

import 'package:flutter/services.dart';

import 'src/models.dart';

export 'src/models.dart';

/// Entry point to the on-device RASP engine.
///
/// The engine is headless: detection, policy and reactions all run on the device, with no server.
class Rasp {
  Rasp._();

  static const MethodChannel _channel = MethodChannel('flutter_rasp');
  static const EventChannel _events = EventChannel('flutter_rasp/events');

  static Stream<ThreatEvent>? _eventStream;

  /// Starts background scanning and returns the first report.
  static Future<SecurityReport> start(RaspConfig config) async {
    final result = await _channel.invokeMapMethod<Object?, Object?>('start', config.toMap());
    return SecurityReport.fromMap(result!);
  }

  /// Runs every detector now.
  static Future<SecurityReport> check() async {
    final result = await _channel.invokeMapMethod<Object?, Object?>('check');
    return SecurityReport.fromMap(result!);
  }

  /// Runs a fresh scan and says whether [flow] may proceed under the current policy.
  static Future<GuardResult> guard(String flow) async {
    final result = await _channel.invokeMapMethod<Object?, Object?>('guard', {'flow': flow});
    return GuardResult.fromMap(result!);
  }

  /// Blocks screenshots and screen recording of the app window (FLAG_SECURE), e.g. on a PIN screen.
  static Future<void> setSecureScreen(bool enabled) =>
      _channel.invokeMethod<void>('setSecureScreen', {'enabled': enabled});

  /// Threat events recorded on the device, oldest first.
  static Future<List<ThreatEvent>> eventLog() async {
    final result = await _channel.invokeListMethod<Map<Object?, Object?>>('eventLog');
    return [for (final event in result ?? const <Map<Object?, Object?>>[]) ThreatEvent.fromMap(event)];
  }

  static Future<void> clearEventLog() => _channel.invokeMethod<void>('clearEventLog');

  /// Threats that became active since the previous scan.
  static Stream<ThreatEvent> get events => _eventStream ??= _events
      .receiveBroadcastStream()
      .map((event) => ThreatEvent.fromMap(event as Map<Object?, Object?>))
      .asBroadcastStream();
}
