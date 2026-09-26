import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_rasp/flutter_rasp.dart';

import '../rasp_setup.dart';
import 'bank.dart';

/// Backend base URL, e.g. `--dart-define=BANK_SERVER=http://10.0.2.2:8787` for the reference server
/// (verifier/rasp_verifier/server.py) seen from an Android emulator. Empty = offline demo.
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

/// Client for the reference bank backend: device binding with Key Attestation, then signed transfers.
class BankApi {
  BankApi._();

  static final instance = BankApi._();

  bool get enabled => bankServer.isNotEmpty;

  String? sessionToken;
  String? deviceId;
  String? securityLevel;
  bool userAuthRequired = false;

  final _http = HttpClient()..connectionTimeout = const Duration(seconds: 10);

  Future<Map<String, Object?>> _post(String path, Map<String, Object?> body, {Set<int> ok = const {200, 201}}) async {
    final request = await _http.postUrl(Uri.parse('$bankServer$path'));
    request.headers.contentType = ContentType.json;
    // Explicit length: the reference server does not read chunked bodies.
    final bytes = utf8.encode(jsonEncode(body));
    request.contentLength = bytes.length;
    request.add(bytes);
    final response = await request.close();
    final decoded = jsonDecode(await response.transform(utf8.decoder).join()) as Map<String, Object?>;
    if (!ok.contains(response.statusCode)) {
      throw BankApiException('${response.statusCode}: ${decoded['reason'] ?? decoded['error']}');
    }
    return decoded;
  }

  /// Logs the customer in; binding and transfers need the session.
  Future<void> login({required String customerId, required String pin}) async {
    final result = await _post('/v1/sessions', {'customerId': customerId, 'pin': pin});
    sessionToken = result['sessionToken']! as String;
  }

  String get _session => sessionToken ?? (throw BankApiException('not logged in'));

  /// Binds this install to a hardware-backed key, attested for the server's challenge. The key needs the user's
  /// biometric or device credential for every signature, so malware cannot sign transfers silently.
  Future<void> bindDevice() async {
    final challenge = await _post('/v1/challenge', {'sessionToken': _session, 'purpose': 'bind'});
    final nonce = challenge['nonce']! as String;
    final binding = await Rasp.bindDevice(Uint8List.fromList(base64Decode(nonce)));
    final result = await _post('/v1/devices', {
      'sessionToken': _session,
      'challenge': nonce,
      'publicKey': binding.publicKey,
      'certificateChain': binding.certificateChain,
    });
    deviceId = result['deviceId']! as String;
    securityLevel = result['securityLevel'] as String?;
    userAuthRequired = result['userAuthRequired'] == true;
  }

  /// Signs the transfer and the RASP verdict with the bound key; the server verifies and decides.
  Future<TransferResult> transfer({required String payee, required int amountCents}) async {
    final id = deviceId ?? (throw BankApiException('device is not bound'));
    final challenge = await _post('/v1/challenge', {'sessionToken': _session, 'purpose': 'transfer', 'deviceId': id});
    final signed = await Rasp.signTransaction(
      flow: Flows.transfer,
      nonce: challenge['nonce']! as String,
      fields: {'payee': payee, 'amountCents': '$amountCents', 'currency': 'USD'},
      confirmationTitle: 'Confirm transfer',
      confirmationText: 'Send ${formatCents(amountCents)} to $payee',
    );
    final result = await _post(
      '/v1/transfers',
      {'sessionToken': _session, 'deviceId': id, 'signedData': signed.signedData, 'signature': signed.signature},
      ok: {200, 403},
    );
    final decision = switch (result['decision']) {
      'allow' => ServerDecision.allow,
      'step_up' => ServerDecision.stepUp,
      'deny' => ServerDecision.deny,
      _ => throw BankApiException('rejected: ${result['reason'] ?? result['error']}'),
    };
    return TransferResult(decision, ((result['reasons'] as List?) ?? const []).cast<String>());
  }
}
