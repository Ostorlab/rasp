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

  /// Stops scans, cancels delayed reactions and discards the session key.
  static Future<void> stop() => _channel.invokeMethod<void>('stop');

  /// Executes HTTPS with normal trust and hostname checks plus configured SPKI pins.
  static Future<RaspResponse> request({
    required String url,
    String method = 'GET',
    Map<String, String> headers = const {},
    Uint8List? body,
  }) async {
    final result = await _channel.invokeMapMethod<Object?, Object?>('request', {
      'url': url,
      'method': method,
      'headers': headers,
      'body': body ?? Uint8List(0),
    });
    return RaspResponse.fromMap(result!);
  }

  /// Requests a real Google Play Integrity standard token bound to the server nonce.
  static Future<String> playIntegrityToken({
    required String nonce,
    required int cloudProjectNumber,
  }) async => (await _channel.invokeMethod<String>('playIntegrityToken', {
    'nonce': nonce,
    'cloudProjectNumber': cloudProjectNumber,
  }))!;

  static Future<void> securePut(String key, Uint8List value) =>
      _channel.invokeMethod<void>('securePut', {'key': key, 'value': value});
  static Future<Uint8List?> secureGet(String key) =>
      _channel.invokeMethod<Uint8List>('secureGet', {'key': key});
  static Future<void> secureDelete(String key) =>
      _channel.invokeMethod<void>('secureDelete', {'key': key});

  /// Deletes the wrapping key and stored ciphertext. Restoring ciphertext cannot restore the key.
  static Future<void> secureClear() =>
      _channel.invokeMethod<void>('secureClear');

  /// Fetches a newer signed policy through bootstrap pins, including when the cached policy expired.
  static Future<void> refreshPolicy(String url) =>
      _channel.invokeMethod<void>('refreshPolicy', {'url': url});

  /// Installs an authenticated, unexpired policy with a strictly newer revision.
  static Future<void> applyPolicy(String envelope) =>
      _channel.invokeMethod<void>('applyPolicy', {'envelope': envelope});

  /// Starts background scanning and returns the first report.
  static Future<SecurityReport> start(RaspConfig config) async {
    final result = await _channel.invokeMapMethod<Object?, Object?>(
      'start',
      config.toMap(),
    );
    return SecurityReport.fromMap(result!);
  }

  /// Runs every detector now.
  static Future<SecurityReport> check() async {
    final result = await _channel.invokeMapMethod<Object?, Object?>('check');
    return SecurityReport.fromMap(result!);
  }

  /// Runs a fresh scan and says whether [flow] may proceed under the current policy.
  static Future<GuardResult> guard(String flow) async {
    final result = await _channel.invokeMapMethod<Object?, Object?>('guard', {
      'flow': flow,
    });
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

  /// Generates a real App Attest enrollment object for `/v1/ios/bind` (iOS only).
  static Future<Map<String, Object?>> appAttestBind(String nonce) async =>
      (await _channel.invokeMapMethod<String, Object?>('appAttestBind', {
        'nonce': nonce,
      }))!;

  /// Call only after the trust service accepts the returned enrollment object.
  static Future<void> confirmAppAttestBinding(String keyId) =>
      _channel.invokeMethod<void>('confirmAppAttestBinding', {'keyId': keyId});

  /// Produces the complete `/v1/ios/token` body using an App Attest assertion.
  static Future<Map<String, Object?>> prepareAppAttestToken(
    String nonce,
  ) async => (await _channel.invokeMapMethod<String, Object?>(
    'prepareAppAttestToken',
    {'nonce': nonce},
  ))!;

  /// Whether this install already holds a bound device key.
  static Future<bool> isDeviceBound() async =>
      await _channel.invokeMethod<bool>('isDeviceBound') ?? false;

  /// The stable per-install id the trust service knows this install by.
  static Future<String> installId() async =>
      (await _channel.invokeMethod<String>('installId'))!;

  /// Generates a hardware-backed key attested with the server's [challenge] (16 to 128 random bytes).
  /// Replaces any previous binding.
  ///
  /// With [requireUserAuth] (the default), every signature needs the user's biometric or device credential,
  /// enforced by the secure hardware and visible to the server in the attestation. It needs a secure lock screen.
  static Future<DeviceBindingResult> bindDevice(
    Uint8List challenge, {
    bool requireUserAuth = true,
  }) async {
    final result = await _channel.invokeMapMethod<Object?, Object?>(
      'bindDevice',
      {
        'challenge': base64Encode(challenge),
        'requireUserAuth': requireUserAuth,
      },
    );
    return DeviceBindingResult.fromMap(result!);
  }

  static Future<void> unbindDevice() =>
      _channel.invokeMethod<void>('unbindDevice');

  /// Seals a fresh RASP report bound to the trust service's [nonce] and authorizes a token: the user-auth
  /// install key signs a proof over the challenge, the report MAC and a new ephemeral session key. One
  /// biometric prompt (showing [confirmationText]) per token; the session key then signs each request
  /// silently via [signRequest].
  ///
  /// Send the result to the trust service's `/v1/token` (see [TokenAuthorization.toRequest]). Throws a
  /// PlatformException with code `auth_cancelled` if the user declines, or `auth_unsupported` below Android 9.
  static Future<TokenAuthorization> prepareToken({
    required String nonce,
    String confirmationTitle = 'Authorize',
    String? confirmationText,
  }) async {
    final result = await _channel.invokeMapMethod<Object?, Object?>(
      'prepareToken',
      {
        'nonce': nonce,
        'confirmationTitle': confirmationTitle,
        'confirmationText': confirmationText,
      },
    );
    return TokenAuthorization.fromMap(result!);
  }

  /// Signs the DPoP proof for one API request with the current session key (silent, no prompt). [body] is
  /// the exact request body bytes that will be sent. Call [prepareToken] first.
  static Future<RequestProof> signRequest({
    required String method,
    required String path,
    required Uint8List body,
  }) async {
    final result = await _channel.invokeMapMethod<Object?, Object?>(
      'signRequest',
      {'method': method, 'path': path, 'body': body},
    );
    return RequestProof.fromMap(result!);
  }

  /// Threat events recorded on the device, oldest first.
  static Future<List<ThreatEvent>> eventLog() async {
    final result = await _channel.invokeListMethod<Map<Object?, Object?>>(
      'eventLog',
    );
    return [
      for (final event in result ?? const <Map<Object?, Object?>>[])
        ThreatEvent.fromMap(event),
    ];
  }

  static Future<void> clearEventLog() =>
      _channel.invokeMethod<void>('clearEventLog');

  /// Threats that became active since the previous scan.
  static Stream<ThreatEvent> get events => _eventStream ??= _events
      .receiveBroadcastStream()
      .map((event) => ThreatEvent.fromMap(event as Map<Object?, Object?>))
      .asBroadcastStream();
}
