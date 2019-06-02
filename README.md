# Elliptic curve cryptography (ECC) in Dart

Elliptic curve cryptography lib for VIZ based blockchain in Dart lang. Forked from [eosdart_ecc](https://github.com/primes-network/eosdart_ecc).

[![Build Status](https://travis-ci.com/VizTower/viz_dart_ecc.svg?branch=master)](https://travis-ci.com/VizTower/viz_dart_ecc)

## Usage

A simple usage example:

```dart
import 'package:viz_dart_ecc/viz_dart_ecc.dart';

void main() {
  VIZPrivateKey privateKey = VIZPrivateKey.fromString(
      '5J2XSYiA62K5s9vLsXXpj9CdoGmWUnohEWnVmg8aJb8D2TYvpbW');

  VIZPublicKey publicKey = privateKey.toPublicKey();

  print('Pub key: ' + publicKey.toString());

  VIZSignature signature = privateKey.signString('data');

  print('Signed data: ' + signature.toString());
}
```

## Features and bugs

Please file feature requests and bugs at the [issue tracker](https://github.com/VizTower/viz_dart_ecc/issues).