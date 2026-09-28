import 'dart:convert';
import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:flutter_rasp/flutter_rasp.dart';

const bankServer = String.fromEnvironment('BANK_SERVER');

enum ServerDecision { allow, stepUp, deny }

class TransferResult {
  const TransferResult(this.decision, this.reasons);

  final ServerDecision decision;
  final List<String> reasons;
}

class BankApiException implements Exception {
  BankApiException(this.message);

  final String message;

  @override
  String toString() => message;
}

/// Client for the reference server (trust service + bank). Binds the install with Key Attestation, gets a
/// short-lived integrity token, then attaches a per-request DPoP proof to each transfer.
class BankApi {
  BankApi._();

  static final instance = BankApi._();

  bool get enabled => bankServer.isNotEmpty;

  String? sessionToken;
  String? installId;
  String? deviceSecurityLevel;
  bool userAuthRequired = false;

  /// POSTs [body] as JSON and returns the decoded response, adding any [headers]. Returns the exact bytes
  /// sent too, so a caller can sign them.
  Future<(Map<String, Object?>, Uint8List)> _post(
    String path,
    Map<String, Object?> body, {
    Map<String, String> headers = const {},
    Set<int> ok = const {200, 201},
  }) async {
    final bytes = Uint8List.fromList(utf8.encode(jsonEncode(body)));
    final response = await Rasp.request(
      url: '$bankServer$path',
      method: 'POST',
      headers: {'Content-Type': 'application/json', ...headers},
      body: bytes,
    );
    final decoded =
        jsonDecode(utf8.decode(response.body)) as Map<String, Object?>;
    if (!ok.contains(response.status)) {
      throw BankApiException(
        '${response.status}: ${decoded['reason'] ?? decoded['error']}',
      );
    }
    return (decoded, bytes);
  }

  Future<Map<String, Object?>> _challenge(String purpose) async {
    final (body, _) = await _post('/v1/challenge', {
      'installId': installId,
      'purpose': purpose,
    });
    return body;
  }

  Future<void> login({required String customerId, required String pin}) async {
    final (result, _) = await _post('/v1/sessions', {
      'customerId': customerId,
      'pin': pin,
    });
    sessionToken = result['sessionToken']! as String;
    installId = await Rasp.installId();
    if (!await Rasp.isDeviceBound()) {
      await _bind();
    }
  }

  String get _session =>
      sessionToken ?? (throw BankApiException('not logged in'));

  /// Binds this install to a hardware-backed key attested for the trust service's challenge.
  Future<void> _bind() async {
    if (Platform.isIOS) {
      final challenge = await _challenge('ios-bind');
      final binding = await Rasp.appAttestBind(challenge['nonce']! as String);
      final (result, _) = await _post('/v1/ios/bind', binding, ok: {201});
      await Rasp.confirmAppAttestBinding(binding['keyId']! as String);
      deviceSecurityLevel = result['securityLevel'] as String?;
      userAuthRequired = false;
      return;
    }
    final challenge = await _challenge('bind');
    final binding = await Rasp.bindDevice(
      Uint8List.fromList(base64Decode(challenge['nonce']! as String)),
    );
    installId = binding.installId;
    final (result, _) = await _post(
      '/v1/bind',
      {
        'installId': binding.installId,
        'nonce': challenge['nonce'],
        'publicKey': binding.publicKey,
        'certificateChain': binding.certificateChain,
        'playIntegrityToken': ?await _playIntegrityToken(
          challenge['nonce']! as String,
        ),
      },
      ok: {201},
    );
    deviceSecurityLevel = result['securityLevel'] as String?;
    userAuthRequired = result['userAuthRequired'] == true;
  }

  /// Authorizes and fetches a short-lived integrity token. The biometric prompt shows [confirmationText].
  Future<String> _token(String confirmationText) async {
    if (Platform.isIOS) {
      final challenge = await _challenge('ios-token');
      final authorization = await Rasp.prepareAppAttestToken(
        challenge['nonce']! as String,
      );
      final (result, _) = await _post('/v1/ios/token', authorization);
      return result['token']! as String;
    }
    final challenge = await _challenge('token');
    final nonce = challenge['nonce']! as String;
    final auth = await Rasp.prepareToken(
      nonce: nonce,
      confirmationTitle: 'Confirm',
      confirmationText: confirmationText,
    );
    final (result, _) = await _post(
      '/v1/token',
      auth.toRequest(
        nonce,
        playIntegrityToken: await _playIntegrityToken(nonce),
      ),
    );
    return result['token']! as String;
  }

  /// Signs the transfer with the session key and attaches the integrity token; the server decides.
  Future<TransferResult> transfer({
    required String payee,
    required int amountCents,
  }) async {
    final token = await _token('Send ${_dollars(amountCents)} to $payee');
    final body = {
      'sessionToken': _session,
      'payee': payee,
      'amountCents': amountCents,
      'currency': 'USD',
    };
    final raw = Uint8List.fromList(utf8.encode(jsonEncode(body)));
    final proof = await Rasp.signRequest(
      method: 'POST',
      path: '/v1/transfers',
      body: raw,
    );

    // Send the exact signed bytes with the proof headers.
    final response = await Rasp.request(
      url: '$bankServer/v1/transfers',
      method: 'POST',
      headers: {'Content-Type': 'application/json', ...proof.headers(token)},
      body: raw,
    );
    final result =
        jsonDecode(utf8.decode(response.body)) as Map<String, Object?>;
    if (response.status != 200 && response.status != 403) {
      throw BankApiException(
        '${response.status}: ${result['reason'] ?? result['error']}',
      );
    }
    final decision = switch (result['decision']) {
      'allow' => ServerDecision.allow,
      'step_up' => ServerDecision.stepUp,
      'deny' => ServerDecision.deny,
      _ => throw BankApiException(
        'rejected: ${result['reason'] ?? result['error']}',
      ),
    };
    return TransferResult(
      decision,
      ((result['reasons'] as List?) ?? const []).cast<String>(),
    );
  }

  /// Zero explicitly selects the backend's degraded mode for local demos.
  Future<String?> _playIntegrityToken(String nonce) async {
    const project = int.fromEnvironment('PLAY_INTEGRITY_PROJECT');
    return project == 0
        ? null
        : Rasp.playIntegrityToken(nonce: nonce, cloudProjectNumber: project);
  }

  String _dollars(int cents) => '\$${(cents / 100).toStringAsFixed(2)}';
}
