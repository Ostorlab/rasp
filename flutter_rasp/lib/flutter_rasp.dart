/// Offline runtime application self-protection for Flutter apps (Android).
library;

import 'dart:convert';

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

  /// Full protection for a sensitive screen (PIN, transfer confirmation): no screenshots or recording, other apps'
  /// overlays hidden, touches through overlays dropped and reported, content hidden from accessibility services that
  /// are not assistive tools. Turn it off when the screen closes.
  static Future<void> setSensitiveScreen(bool enabled) =>
      _channel.invokeMethod<void>('setSensitiveScreen', {'enabled': enabled});

  /// Whether this install already holds a bound device key.
  static Future<bool> isDeviceBound() async => await _channel.invokeMethod<bool>('isDeviceBound') ?? false;

  /// Generates a hardware-backed key attested with the server's [challenge] (16 to 128 random bytes).
  /// Replaces any previous binding.
  ///
  /// With [requireUserAuth] (the default), every signature needs the user's biometric or device credential,
  /// enforced by the secure hardware and visible to the server in the attestation. It needs a secure lock screen.
  static Future<DeviceBindingResult> bindDevice(Uint8List challenge, {bool requireUserAuth = true}) async {
    final result = await _channel.invokeMapMethod<Object?, Object?>('bindDevice', {
      'challenge': base64Encode(challenge),
      'requireUserAuth': requireUserAuth,
    });
    return DeviceBindingResult.fromMap(result!);
  }

  static Future<void> unbindDevice() => _channel.invokeMethod<void>('unbindDevice');

  /// Runs a fresh scan for [flow] and signs [fields] plus the verdict with the bound key.
  /// The [nonce] comes from the server, so a signed transaction cannot be replayed.
  ///
  /// For a user-auth key, the system prompt shows [confirmationTitle] and [confirmationText]; describe exactly what
  /// is being signed ("Send \$50.00 to Alex Smith"). Throws a PlatformException with code `auth_cancelled` if the
  /// user declines.
  static Future<SignedTransaction> signTransaction({
    required String flow,
    required String nonce,
    required Map<String, String> fields,
    String confirmationTitle = 'Confirm',
    String? confirmationText,
  }) async {
    final result = await _channel.invokeMapMethod<Object?, Object?>('signTransaction', {
      'flow': flow,
      'nonce': nonce,
      'fields': fields,
      'confirmationTitle': confirmationTitle,
      'confirmationText': confirmationText,
    });
    return SignedTransaction.fromMap(result!);
  }

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
