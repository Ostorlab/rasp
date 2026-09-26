import 'package:flutter/material.dart';
import 'package:flutter_rasp/flutter_rasp.dart';

import '../data/bank.dart';
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
    // No screenshots or screen recording while the PIN is on screen.
    Rasp.setSecureScreen(true);
  }

  @override
  void dispose() {
    Rasp.setSecureScreen(false);
    _pin.dispose();
    super.dispose();
  }

  void _login() {
    if (_pin.text != Bank.pin) {
      setState(() => _error = 'Wrong PIN (hint: ${Bank.pin})');
      return;
    }
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
