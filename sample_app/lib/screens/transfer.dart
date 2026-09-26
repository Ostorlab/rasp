import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_rasp/flutter_rasp.dart';

import '../data/bank.dart';
import '../data/bank_api.dart';
import '../main.dart';
import '../rasp_setup.dart';

class TransferScreen extends StatefulWidget {
  const TransferScreen({super.key});

  @override
  State<TransferScreen> createState() => _TransferScreenState();
}

class _TransferScreenState extends State<TransferScreen> {
  final _payee = TextEditingController(text: 'Alex Smith');
  final _amount = TextEditingController(text: '50.00');
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    Rasp.setSensitiveScreen(true);
  }

  @override
  void dispose() {
    Rasp.setSensitiveScreen(false);
    _payee.dispose();
    _amount.dispose();
    super.dispose();
  }

  Future<bool> _confirm(String title, String message, {String confirm = 'Continue'}) async =>
      await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          icon: const Icon(Icons.warning_amber),
          title: Text(title),
          content: Text(message),
          actions: [
            TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
            TextButton(key: const Key('confirm'), onPressed: () => Navigator.pop(context, true), child: Text(confirm)),
          ],
        ),
      ) ??
      false;

  Future<void> _inform(String title, String message) => showDialog<void>(
        context: context,
        builder: (context) => AlertDialog(
          icon: const Icon(Icons.block),
          title: Text(title),
          content: Text(message),
          actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text('OK'))],
        ),
      );

  Future<void> _send() async {
    final cents = ((double.tryParse(_amount.text) ?? 0) * 100).round();
    if (cents <= 0) return;
    setState(() => _busy = true);
    try {
      await _sendChecked(cents);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _sendChecked(int cents) async {
    // Ask the RASP engine right before the sensitive action, not just at startup.
    final guard = await Rasp.guard(Flows.transfer);
    if (!mounted) return;
    if (!guard.allowed) {
      await _inform('Transfer blocked',
          'This device is not safe for payments: ${guard.blockingThreats.map(threatLabel).join(', ')}.');
      return;
    }
    if (guard.warnings.contains(ThreatType.activeCall)) {
      final proceed = await _confirm(
        'Are you on a call?',
        'If someone on the phone is asking you to move money, hang up. Demo Bank will never ask you to '
            'transfer money to "protect" it.',
        confirm: 'Nobody asked me',
      );
      if (!proceed || !mounted) return;
    }

    final api = BankApi.instance;
    if (api.enabled) {
      final TransferResult result;
      try {
        result = await api.transfer(payee: _payee.text, amountCents: cents);
      } on Exception catch (e) {
        // The user declining the confirmation prompt is not an error.
        if (e is PlatformException && e.code == 'auth_cancelled') return;
        if (mounted) await _inform('Transfer failed', '$e');
        return;
      }
      if (!mounted) return;
      switch (result.decision) {
        case ServerDecision.deny:
          await _inform('Transfer refused by the bank', result.reasons.join(', '));
          return;
        case ServerDecision.stepUp:
          // A real bank would send an out-of-band OTP or call back; the demo asks for confirmation.
          final ok = await _confirm('Extra verification', 'The bank needs to confirm this transfer (${result.reasons.join(', ')}).',
              confirm: 'Confirm');
          if (!ok || !mounted) return;
        case ServerDecision.allow:
          break;
      }
    }

    Bank.instance.transfer(_payee.text, cents);
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Sent ${formatCents(cents)} to ${_payee.text}')));
    Navigator.pop(context);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Transfer')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            TextField(controller: _payee, decoration: const InputDecoration(labelText: 'Payee', border: OutlineInputBorder())),
            const SizedBox(height: 16),
            TextField(
              controller: _amount,
              keyboardType: const TextInputType.numberWithOptions(decimal: true),
              decoration: const InputDecoration(labelText: 'Amount', prefixText: '\$ ', border: OutlineInputBorder()),
            ),
            const SizedBox(height: 24),
            SizedBox(
              width: double.infinity,
              child: FilledButton(
                key: const Key('send'),
                onPressed: _busy ? null : _send,
                child: _busy ? const SizedBox.square(dimension: 20, child: CircularProgressIndicator(strokeWidth: 2)) : const Text('Send'),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
