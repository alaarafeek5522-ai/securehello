import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Secure Hello',
      debugShowCheckedModeBanner: false,
      home: const SecurityGate(),
    );
  }
}

class SecurityGate extends StatefulWidget {
  const SecurityGate({super.key});
  @override
  State<SecurityGate> createState() => _SecurityGateState();
}

class _SecurityGateState extends State<SecurityGate> {
  static const _channel = MethodChannel('com.alaa.securehello/security');
  String _status = 'Checking...';
  bool _passed = false;

  @override
  void initState() {
    super.initState();
    _runChecks();
  }

  Future<void> _runChecks() async {
    try {
      final result = await _channel.invokeMethod<Map>('runSecurityChecks');
      final ok = result?['passed'] == true;
      setState(() {
        _passed = ok;
        _status = ok ? 'Secure ✅' : 'Security Failed ❌\n${result?['reason']}';
      });
    } catch (e) {
      setState(() {
        _status = 'Error: $e';
        _passed = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: _passed ? Colors.black : Colors.red[900],
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              _passed ? Icons.lock : Icons.lock_open,
              color: Colors.white,
              size: 64,
            ),
            const SizedBox(height: 24),
            Text(
              _passed ? 'Hello, World!' : 'BLOCKED',
              style: const TextStyle(
                color: Colors.white,
                fontSize: 32,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 16),
            Text(
              _status,
              style: const TextStyle(color: Colors.white70, fontSize: 14),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}
