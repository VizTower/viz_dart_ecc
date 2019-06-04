# Elliptic curve cryptography (ECC) in Dart ![Pub](https://img.shields.io/pub/v/viz_dart_ecc.svg)
[![Build Status](https://travis-ci.com/VizTower/viz_dart_ecc.svg?branch=master)](https://travis-ci.com/VizTower/viz_dart_ecc)

[[DOC](https://pub.dev/documentation/viz_dart_ecc/latest/) | [issue tracker](https://github.com/VizTower/viz_dart_ecc/issues)]

viz_dart_ecc is cryptography library for simply data encoding and decoding 
using VIZ blockchain's ECC cryptography algorithms. 

Code for viz_dart_ecc was forked from [eosdart_ecc](https://github.com/primes-network/eosdart_ecc) 
but most of it was rewritten for VIZ blockchain.

## Usage

A simple usage example:

```dart
import 'package:viz_dart_ecc/viz_dart_ecc.dart';

void main() {
  VIZPrivateKey privateKey = VIZPrivateKey.fromString(
      '5J2XSYiA62K5s9vLsXXpj9CdoGmWUnohEWnVmg8aJb8D2TYvpbW');

  VIZPublicKey publicKey = privateKey.toPublicKey();
  VIZSignature signature = privateKey.signString('data');

  print('Pub key: ' + publicKey.toString());
  print('Signatured data: ' + signature.toString());
}
```

## Features and bugs

Please file feature requests and bugs at the [issue tracker](https://github.com/VizTower/viz_dart_ecc/issues)