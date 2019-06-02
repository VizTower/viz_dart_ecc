import 'package:viz_dart_ecc/viz_dart_ecc.dart';
import 'package:test/test.dart';

void main() {
  group('VIZ signature tests.', () {
    test('Construct VIZ signature from string', () {
      String sigStr =
          '2030fe8c87efe5524e8f555bdf049b33cef2d82f33a312f0e731d21f20d60844376ea1330d592b9d62d7d3766b80f1c40a71564c4bb7a9958bc74cf757d9e97429';
      VIZSignature signature = VIZSignature.fromString(sigStr);
      print(signature);

      expect(sigStr, signature.toString());
    });
  });
}
