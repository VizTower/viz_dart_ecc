import 'package:convert/convert.dart';
import 'package:viz_dart_ecc/viz_dart_ecc.dart';
import 'package:test/test.dart';

void main() {
  group('VIZ Key tests.', () {
    test('Construct VIZ public key from string', () {
      VIZPublicKey publicKey = VIZPublicKey.fromString(
          'VIZ8VmBfvDi5S2Y8pB4T5AyfZmmqGBL2jV4t5H5cZbonp1VgSWh3u');
      print(publicKey);

      expect('VIZ8VmBfvDi5S2Y8pB4T5AyfZmmqGBL2jV4t5H5cZbonp1VgSWh3u',
          publicKey.toString());
    });

    test('Construct VIZ private key from string', () {
      // common private key
      VIZPrivateKey privateKey = VIZPrivateKey.fromString(
          '5KWh6ThtRJfjzTJJ4EWkugrzLV1zVXZWSFPg3qTae2uTTq8pM9U');
      expect('VIZ8VmBfvDi5S2Y8pB4T5AyfZmmqGBL2jV4t5H5cZbonp1VgSWh3u',
          privateKey.toPublicKey().toString());
      expect('5KWh6ThtRJfjzTJJ4EWkugrzLV1zVXZWSFPg3qTae2uTTq8pM9U',
          privateKey.toString());
    });

    test('Invalid VIZ private key', () {
      try {
        VIZPrivateKey.fromString(
            '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjsm');
        fail('Should be invalid private key');
      } on InvalidKey {} catch (e) {
        fail('Should throw InvalidKey exception');
      }
    });

    test('Construct random VIZ private key from seed', () {
      VIZPrivateKey privateKey = VIZPrivateKey.fromSeed('abc');
      print(privateKey);
      print(privateKey.toPublicKey());

      VIZPrivateKey privateKey2 =
          VIZPrivateKey.fromString(privateKey.toString());
      expect(privateKey.toPublicKey().toString(),
          privateKey2.toPublicKey().toString());
    });

    test('Construct random VIZ private key', () {
      VIZPrivateKey privateKey = VIZPrivateKey.fromRandom();

      print(privateKey);
      print(privateKey.toPublicKey());

      VIZPrivateKey privateKey2 =
          VIZPrivateKey.fromString(privateKey.toString());
      expect(privateKey.toPublicKey().toString(),
          privateKey2.toPublicKey().toString());
    });

    test('Sign transaction with VIZ private key', () {
      VIZPrivateKey privateKey = VIZPrivateKey.fromString(
          '5J2XSYiA62K5s9vLsXXpj9CdoGmWUnohEWnVmg8aJb8D2TYvpbW');
      VIZSignature signature = privateKey.sign(hex.decode('ff00ee65'));

      print(signature.toString());

      expect(signature.toString(),
          '1f02a25804ad71bd4226486f94dcad358426e5bde9a68eb69e5ed18552d81843df011c1d598c7d4451b6d0fe3c3e7f885c46b88577616895fcef80eb82ae9ba288');
    });
  });
}
