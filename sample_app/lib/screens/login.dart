import 'package:flutter/material.dart';
import 'package:flutter_rasp/flutter_rasp.dart';

import '../data/bank.dart';
import '../data/bank_api.dart';
import 'home.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _pin = TextEditingController();
  String? _error;

  @override
  void initState() {
    super.initState();
    // PIN on screen: no screenshots or recording, no overlays, hidden from non-assistive accessibility services.
    Rasp.setSensitiveScreen(true);
  }

  @override
  void dispose() {
    Rasp.setSensitiveScreen(false);
    _pin.dispose();
    super.dispose();
  }

  Future<void> _login() async {
    if (_pin.text != Bank.pin) {
      setState(() => _error = 'Wrong PIN (hint: ${Bank.pin})');
      return;
    }
    final api = BankApi.instance;
    if (api.enabled) {
      try {
        await api.login(customerId: 'demo', pin: _pin.text);
        if (api.deviceId == null) await api.bindDevice();
      } on Exception catch (e) {
        if (!mounted) return;
        setState(() => _error = 'Sign-in failed: $e');
        return;
      }
    }
    if (!mounted) return;
    Navigator.pushReplacement(context, MaterialPageRoute<void>(builder: (_) => const HomeScreen()));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(Icons.account_balance, size: 64, color: Theme.of(context).colorScheme.primary),
              const SizedBox(height: 16),
              Text('Demo Bank', style: Theme.of(context).textTheme.headlineMedium),
              const SizedBox(height: 32),
              TextField(
                key: const Key('pin'),
                controller: _pin,
                obscureText: true,
                keyboardType: TextInputType.number,
                maxLength: 4,
                decoration: InputDecoration(labelText: 'PIN', errorText: _error, border: const OutlineInputBorder()),
                onSubmitted: (_) => _login(),
              ),
              const SizedBox(height: 16),
              SizedBox(
                width: double.infinity,
                child: FilledButton(key: const Key('login'), onPressed: _login, child: const Text('Log in')),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
