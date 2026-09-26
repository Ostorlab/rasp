import 'package:flutter/material.dart';
import 'package:flutter_rasp/flutter_rasp.dart';

import '../main.dart';

/// Shows what the on-device RASP engine sees. A production app would not expose this to users.
class SecurityScreen extends StatefulWidget {
  const SecurityScreen({super.key});

  @override
  State<SecurityScreen> createState() => _SecurityScreenState();
}

class _SecurityScreenState extends State<SecurityScreen> {
  SecurityReport? _report;
  List<ThreatEvent> _events = const [];

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    final report = await Rasp.check();
    final events = await Rasp.eventLog();
    if (!mounted) return;
    setState(() {
      _report = report;
      _events = events.reversed.toList();
    });
  }

  @override
  Widget build(BuildContext context) {
    final report = _report;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Security status'),
        actions: [IconButton(tooltip: 'Scan again', onPressed: _refresh, icon: const Icon(Icons.refresh))],
      ),
      body: report == null
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.all(16),
              children: [
                _RiskCard(report: report),
                const SizedBox(height: 16),
                Text('Signals (${report.signals.length})', style: Theme.of(context).textTheme.titleMedium),
                if (report.signals.isEmpty) const ListTile(title: Text('No threats detected')),
                for (final signal in report.signals)
                  ListTile(
                    contentPadding: EdgeInsets.zero,
                    leading: const Icon(Icons.warning_amber),
                    title: Text('${threatLabel(signal.threat)} · ${signal.confidence}%'),
                    subtitle: Text('${signal.detector}\n${signal.evidence}'),
                    isThreeLine: true,
                  ),
                const SizedBox(height: 16),
                Text('Event log (${_events.length})', style: Theme.of(context).textTheme.titleMedium),
                for (final event in _events)
                  ListTile(
                    contentPadding: EdgeInsets.zero,
                    title: Text(event.newThreats.map(threatLabel).join(', ')),
                    subtitle: Text('${event.timestamp.toLocal()} · ${event.reactions.map((r) => r.name).join(', ')}'),
                  ),
              ],
            ),
    );
  }
}

class _RiskCard extends StatelessWidget {
  const _RiskCard({required this.report});

  final SecurityReport report;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final (color, icon) = switch (report.riskLevel) {
      RiskLevel.none => (Colors.green, Icons.verified_user),
      RiskLevel.low => (Colors.amber, Icons.info_outline),
      RiskLevel.medium => (Colors.orange, Icons.warning_amber),
      RiskLevel.high => (scheme.error, Icons.gpp_bad),
    };
    return Card(
      child: ListTile(
        leading: Icon(icon, color: color, size: 36),
        title: Text('Risk: ${report.riskLevel.name}', key: const Key('risk')),
        subtitle: Text(report.isClean
            ? 'No active threats'
            : report.threats.entries.map((e) => '${threatLabel(e.key)} → ${e.value.map((r) => r.name).join(', ')}').join('\n')),
      ),
    );
  }
}
