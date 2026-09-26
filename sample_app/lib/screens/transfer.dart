import 'package:flutter/material.dart';
import 'package:flutter_rasp/flutter_rasp.dart';

import '../data/bank.dart';
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
  void dispose() {
    _payee.dispose();
    _amount.dispose();
    super.dispose();
  }

  Future<void> _send() async {
    final cents = ((double.tryParse(_amount.text) ?? 0) * 100).round();
    if (cents <= 0) return;
    setState(() => _busy = true);

    // Ask the RASP engine right before the sensitive action, not just at startup.
    final guard = await Rasp.guard(Flows.transfer);
    if (!mounted) return;
    setState(() => _busy = false);

    if (!guard.allowed) {
      await showDialog<void>(
        context: context,
        builder: (context) => AlertDialog(
          icon: const Icon(Icons.block),
          title: const Text('Transfer blocked'),
          content: Text('This device is not safe for payments: ${guard.blockingThreats.map(threatLabel).join(', ')}.'),
          actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text('OK'))],
        ),
      );
      return;
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
