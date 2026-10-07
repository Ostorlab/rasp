import 'dart:convert';
import 'dart:io';
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

  final _http = HttpClient()..connectionTimeout = const Duration(seconds: 10);

  /// POSTs [body] as JSON and returns the decoded response, adding any [headers]. Returns the exact bytes
  /// sent too, so a caller can sign them.
  Future<(Map<String, Object?>, Uint8List)> _post(
    String path,
    Map<String, Object?> body, {
    Map<String, String> headers = const {},
    Set<int> ok = const {200, 201},
  }) async {
    final request = await _http.postUrl(Uri.parse('$bankServer$path'));
    request.headers.contentType = ContentType.json;
    headers.forEach(request.headers.set);
    final bytes = Uint8List.fromList(utf8.encode(jsonEncode(body)));
    request.contentLength = bytes.length;
    request.add(bytes);
    final response = await request.close();
    final decoded = jsonDecode(await response.transform(utf8.decoder).join()) as Map<String, Object?>;
    if (!ok.contains(response.statusCode)) {
      throw BankApiException('${response.statusCode}: ${decoded['reason'] ?? decoded['error']}');
    }
    return (decoded, bytes);
  }

  Future<Map<String, Object?>> _challenge(String purpose) async {
    final (body, _) = await _post('/v1/challenge', {'installId': installId, 'purpose': purpose});
    return body;
  }

  Future<void> login({required String customerId, required String pin}) async {
    final (result, _) = await _post('/v1/sessions', {'customerId': customerId, 'pin': pin});
    sessionToken = result['sessionToken']! as String;
    installId = await Rasp.installId();
    if (!await Rasp.isDeviceBound()) {
      await _bind();
    }
  }

  String get _session => sessionToken ?? (throw BankApiException('not logged in'));

  /// Binds this install to a hardware-backed key attested for the trust service's challenge.
  Future<void> _bind() async {
    final challenge = await _challenge('bind');
    final binding = await Rasp.bindDevice(Uint8List.fromList(base64Decode(challenge['nonce']! as String)));
    installId = binding.installId;
    final (result, _) = await _post('/v1/bind', {
      'installId': binding.installId,
      'nonce': challenge['nonce'],
      'publicKey': binding.publicKey,
      'certificateChain': binding.certificateChain,
      if (await _playIntegrityToken(challenge['nonce']! as String) case final token?) 'playIntegrityToken': token,
    }, ok: {201});
    deviceSecurityLevel = result['securityLevel'] as String?;
    userAuthRequired = result['userAuthRequired'] == true;
  }

  /// Authorizes and fetches a short-lived integrity token. The biometric prompt shows [confirmationText].
  Future<String> _token(String confirmationText) async {
    final challenge = await _challenge('token');
    final nonce = challenge['nonce']! as String;
    final auth = await Rasp.prepareToken(nonce: nonce, confirmationTitle: 'Confirm', confirmationText: confirmationText);
    final (result, _) = await _post(
      '/v1/token',
      auth.toRequest(nonce, playIntegrityToken: await _playIntegrityToken(nonce)),
    );
    return result['token']! as String;
  }

  /// Signs the transfer with the session key and attaches the integrity token; the server decides.
  Future<TransferResult> transfer({required String payee, required int amountCents}) async {
    final token = await _token('Send ${_dollars(amountCents)} to $payee');
    final body = {'sessionToken': _session, 'payee': payee, 'amountCents': amountCents, 'currency': 'USD'};
    final raw = Uint8List.fromList(utf8.encode(jsonEncode(body)));
    final proof = await Rasp.signRequest(method: 'POST', path: '/v1/transfers', body: raw);

    // Send the exact signed bytes with the proof headers.
    final request = await _http.postUrl(Uri.parse('$bankServer/v1/transfers'));
    request.headers.contentType = ContentType.json;
    proof.headers(token).forEach(request.headers.set);
    request.contentLength = raw.length;
    request.add(raw);
    final response = await request.close();
    final result = jsonDecode(await response.transform(utf8.decoder).join()) as Map<String, Object?>;
    if (response.statusCode != 200 && response.statusCode != 403) {
      throw BankApiException('${response.statusCode}: ${result['reason'] ?? result['error']}');
    }
    final decision = switch (result['decision']) {
      'allow' => ServerDecision.allow,
      'step_up' => ServerDecision.stepUp,
      'deny' => ServerDecision.deny,
      _ => throw BankApiException('rejected: ${result['reason'] ?? result['error']}'),
    };
    return TransferResult(decision, ((result['reasons'] as List?) ?? const []).cast<String>());
  }

  /// A real build requests a Play Integrity token (Android) or an App Attest assertion (iOS) bound to the
  /// nonce via requestHash. The demo runs in the trust service's degraded mode (no platform attestation), so
  /// this returns null and the risk floor is raised to medium. See the design, section 7.
  Future<String?> _playIntegrityToken(String nonce) async => null;

  String _dollars(int cents) => '\$${(cents / 100).toStringAsFixed(2)}';
}
