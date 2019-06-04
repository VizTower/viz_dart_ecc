import 'package:viz_dart_ecc/viz_dart_ecc.dart';

void main() {
  VIZPrivateKey privateKey = VIZPrivateKey.fromString(
      '5J2XSYiA62K5s9vLsXXpj9CdoGmWUnohEWnVmg8aJb8D2TYvpbW');

  VIZPublicKey publicKey = privateKey.toPublicKey();
  VIZSignature signature = privateKey.signString('data');

  print('Pub key: ' + publicKey.toString());
  print('Signatured data: ' + signature.toString());
}
