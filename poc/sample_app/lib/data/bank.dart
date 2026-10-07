/// In-memory fake bank data. Nothing here talks to a network.
class Transaction {
  const Transaction(this.label, this.amountCents, this.date);

  final String label;
  final int amountCents;
  final DateTime date;
}

class Bank {
  Bank._();

  static final instance = Bank._();

  static const pin = '1234';

  int balanceCents = 1284350;

  final List<Transaction> transactions = [
    Transaction('Grocery store', -6420, DateTime(2026, 9, 24)),
    Transaction('Salary', 320000, DateTime(2026, 9, 20)),
    Transaction('Electricity bill', -8915, DateTime(2026, 9, 18)),
    Transaction('Coffee', -450, DateTime(2026, 9, 17)),
  ];

  void transfer(String payee, int amountCents) {
    balanceCents -= amountCents;
    transactions.insert(0, Transaction('Transfer to $payee', -amountCents, DateTime.now()));
  }
}

String formatCents(int cents) {
  final sign = cents < 0 ? '-' : '';
  final abs = cents.abs();
  final units = (abs ~/ 100).toString().replaceAllMapped(RegExp(r'\B(?=(\d{3})+(?!\d))'), (_) => ',');
  return '$sign\$$units.${(abs % 100).toString().padLeft(2, '0')}';
}
