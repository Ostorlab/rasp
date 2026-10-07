import 'package:flutter/material.dart';

import '../data/bank.dart';
import 'security.dart';
import 'transfer.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final _bank = Bank.instance;

  Future<void> _open(Widget screen) async {
    await Navigator.push(context, MaterialPageRoute<void>(builder: (_) => screen));
    setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(
        title: const Text('Demo Bank'),
        actions: [
          IconButton(
            key: const Key('security'),
            tooltip: 'Security status',
            icon: const Icon(Icons.shield_outlined),
            onPressed: () => _open(const SecurityScreen()),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Checking account', style: theme.textTheme.labelLarge),
                  const SizedBox(height: 8),
                  Text(formatCents(_bank.balanceCents), key: const Key('balance'), style: theme.textTheme.headlineLarge),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          FilledButton.icon(
            key: const Key('transfer'),
            onPressed: () => _open(const TransferScreen()),
            icon: const Icon(Icons.send),
            label: const Text('Transfer money'),
          ),
          const SizedBox(height: 24),
          Text('Recent activity', style: theme.textTheme.titleMedium),
          for (final tx in _bank.transactions)
            ListTile(
              contentPadding: EdgeInsets.zero,
              title: Text(tx.label),
              subtitle: Text('${tx.date.year}-${tx.date.month.toString().padLeft(2, '0')}-${tx.date.day.toString().padLeft(2, '0')}'),
              trailing: Text(formatCents(tx.amountCents)),
            ),
        ],
      ),
    );
  }
}
