import 'package:convert/convert.dart';
import 'package:viz_dart_ecc/viz_dart_ecc.dart';

void main() {
  VIZPrivateKey privateKey = VIZPrivateKey.fromString(
      '5J2XSYiA62K5s9vLsXXpj9CdoGmWUnohEWnVmg8aJb8D2TYvpbW');
  VIZSignature signature = privateKey.sign(hex.decode(
      'ff00ee565'));

  print(signature.toString());
}
