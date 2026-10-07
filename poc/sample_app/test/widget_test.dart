import 'package:demo_bank/data/bank.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('formatCents', () {
    expect(formatCents(1284350), '\$12,843.50');
    expect(formatCents(-450), '-\$4.50');
    expect(formatCents(5), '\$0.05');
  });

  test('transfer updates balance and history', () {
    final bank = Bank.instance;
    final before = bank.balanceCents;
    bank.transfer('Alex', 5000);
    expect(bank.balanceCents, before - 5000);
    expect(bank.transactions.first.label, 'Transfer to Alex');
  });
}
