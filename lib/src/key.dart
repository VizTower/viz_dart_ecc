import 'dart:typed_data';
import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/src/utils.dart';
import 'package:pointycastle/ecc/api.dart' show ECSignature, ECPoint;

import './exception.dart';
import './key_base.dart';
import './signature.dart';

/// VIZ Public Key
class VIZPublicKey extends VIZKey {
  static final PUB_KEY_PREFIX = 'VIZ';

  ECPoint q;

  /// Construct VIZ public key from buffer
  VIZPublicKey.fromPoint(this.q);

  /// Construct VIZ public key from string
  factory VIZPublicKey.fromString(String keyStr) {
    if (!keyStr.startsWith(PUB_KEY_PREFIX)) {
      throw InvalidKey('A key must begin with "$PUB_KEY_PREFIX"');
    }
    String pupKeyStr = keyStr.substring(3);
    Uint8List keyBuf = VIZKey.decodeKey(pupKeyStr);
    return VIZPublicKey.fromBuffer(keyBuf);
  }

  factory VIZPublicKey.fromBuffer(Uint8List buffer) {
    ECPoint point = VIZKey.secp256k1.curve.decodePoint(buffer);
    return VIZPublicKey.fromPoint(point);
  }

  Uint8List toBuffer() {
    // always compressed
    return q.getEncoded(true);
  }

  String toString() {
    return PUB_KEY_PREFIX + VIZKey.encodeKey(this.toBuffer());
  }
}

/// VIZ Private Key
class VIZPrivateKey extends VIZKey {
  Uint8List d;

  BigInt _r;
  BigInt _s;

  /// Constructor VIZ private key from the key buffer itself
  VIZPrivateKey.fromBuffer(this.d);

  /// Construct the private key from WIF string
  VIZPrivateKey.fromString(String keyStr) {
    // WIF
    Uint8List keyBuf = VIZKey.decodeKey(keyStr, VIZKey.SHA256X2);
    int version = keyBuf.first;
    if (VIZKey.VERSION != version) {
      throw InvalidKey('Expected version ${0x80}, instead got ${version}');
    }

    d = keyBuf.sublist(1, keyBuf.length);
    if (d.lengthInBytes == 33 && d.elementAt(32) == 1) {
      // remove compression flag
      d = d.sublist(0, 32);
    }

    if (d.lengthInBytes != 32) {
      throw InvalidKey('Expecting 32 bytes, got ${d.length}');
    }
  }

  /// Generate VIZ private key from seed. Please note: This is not random!
  /// For the given seed, the generated key would always be the same
  factory VIZPrivateKey.fromSeed(String seed) {
    Digest s = sha256.convert(utf8.encode(seed));
    return VIZPrivateKey.fromBuffer(s.bytes);
  }

  /// Generate the random VIZ private key
  factory VIZPrivateKey.fromRandom() {
    final int randomLimit = 1 << 32;
    Random randomGenerator;
    try {
      randomGenerator = Random.secure();
    } catch (e) {
      randomGenerator = new Random();
    }

    int randomInt1 = randomGenerator.nextInt(randomLimit);
    Uint8List entropy1 = encodeBigInt(BigInt.from(randomInt1));

    int randomInt2 = randomGenerator.nextInt(randomLimit);
    Uint8List entropy2 = encodeBigInt(BigInt.from(randomInt2));

    int randomInt3 = randomGenerator.nextInt(randomLimit);
    Uint8List entropy3 = encodeBigInt(BigInt.from(randomInt3));

    List<int> entropy = entropy1.toList();
    entropy.addAll(entropy2);
    entropy.addAll(entropy3);
    Uint8List randomKey = Uint8List.fromList(entropy);
    Digest d = sha256.convert(randomKey);
    return VIZPrivateKey.fromBuffer(d.bytes);
  }

  /// Check if a private key is WIF format
  static bool isWIF(String wif) {
    try {
      VIZKey.decodeKey(wif, VIZKey.SHA256X2);
      return true;
    } catch (e) {
      return false;
    }
  }

  /// Get the public key string from this private key
  VIZPublicKey toPublicKey() {
    BigInt privateKeyNum = decodeBigInt(this.d);
    ECPoint ecPoint = VIZKey.secp256k1.G * privateKeyNum;

    return VIZPublicKey.fromPoint(ecPoint);
  }

  /// Sign the bytes data using the private key
  VIZSignature sign(Uint8List data) {
    Digest d = sha256.convert(data);
    return signHash(d.bytes);
  }

  /// Sign the string data using the private key
  VIZSignature signString(String data) {
    return sign(utf8.encode(data));
  }

  /// Sign the SHA256 hashed data using the private key
  VIZSignature signHash(Uint8List sha256Data) {
    int nonce = 0;
    BigInt n = VIZKey.secp256k1.n;
    BigInt e = decodeBigInt(sha256Data);

    while (true) {
      _deterministicGenerateK(sha256Data, this.d, e, nonce++);
      var N_OVER_TWO = n >> 1;
      if (_s.compareTo(N_OVER_TWO) > 0) {
        _s = n - _s;
      }
      ECSignature sig = ECSignature(_r, _s);

      Uint8List der = VIZSignature.ecSigToDER(sig);

      int lenR = der.elementAt(3);
      int lenS = der.elementAt(5 + lenR);
      if (lenR == 32 && lenS == 32) {
        int i = VIZSignature.calcPubKeyRecoveryParam(
            decodeBigInt(sha256Data), sig, this.toPublicKey());
        i += 4; // compressed
        i += 27; // compact  //  24 or 27 :( forcing odd-y 2nd key candidate)
        return VIZSignature(i, sig.r, sig.s);
      }
    }
  }

  String toString() {
    List<int> version = List<int>();
    version.add(VIZKey.VERSION);
    Uint8List keyBuf = VIZKey.concat(Uint8List.fromList(version), this.d);

    return VIZKey.encodeKey(keyBuf, VIZKey.SHA256X2);
  }

  BigInt _deterministicGenerateK(
      Uint8List hash, Uint8List x, BigInt e, int nonce) {
    List<int> newHash = hash;
    if (nonce > 0) {
      List<int> addition = Uint8List(nonce);
      List<int> data = List.from(hash)..addAll(addition);
      newHash = sha256.convert(data).bytes;
    }

    // Step B
    Uint8List v = Uint8List(32);
    for (int i = 0; i < v.lengthInBytes; i++) {
      v[i] = 1;
    }

    // Step C
    Uint8List k = Uint8List(32);

    // Step D
    List<int> d1 = List.from(v)
      ..add(0)
      ..addAll(x)
      ..addAll(newHash);

    Hmac hMacSha256 = new Hmac(sha256, k); // HMAC-SHA256
    k = hMacSha256.convert(d1).bytes;

    // Step E
    hMacSha256 = new Hmac(sha256, k); // HMAC-SHA256
    v = hMacSha256.convert(v).bytes;

    // Step F
    List<int> d2 = List.from(v)
      ..add(1)
      ..addAll(x)
      ..addAll(newHash);

    k = hMacSha256.convert(d2).bytes;

    // Step G
    hMacSha256 = new Hmac(sha256, k); // HMAC-SHA256
    v = hMacSha256.convert(v).bytes;
    // Step H1/H2a, again, ignored as tlen === qlen (256 bit)
    // Step H2b again
    v = hMacSha256.convert(v).bytes;

    BigInt T = decodeBigInt(v);
    // Step H3, repeat until T is within the interval [1, n - 1]
    while (T.sign <= 0 ||
        T.compareTo(VIZKey.secp256k1.n) >= 0 ||
        !_checkSig(e, newHash, T)) {
      List<int> d3 = List.from(v)..add(0);
      k = hMacSha256.convert(d3).bytes;
      hMacSha256 = new Hmac(sha256, k); // HMAC-SHA256
      v = hMacSha256.convert(v).bytes;
      // Step H1/H2a, again, ignored as tlen === qlen (256 bit)
      // Step H2b again
      v = hMacSha256.convert(v).bytes;

      T = decodeBigInt(v);
    }
    return T;
  }

  bool _checkSig(BigInt e, Uint8List hash, BigInt k) {
    BigInt n = VIZKey.secp256k1.n;
    ECPoint Q = VIZKey.secp256k1.G * k;

    if (Q.isInfinity) {
      return false;
    }

    _r = Q.x.toBigInteger() % n;
    if (_r.sign == 0) {
      return false;
    }

    _s = k.modInverse(VIZKey.secp256k1.n) * (e + decodeBigInt(d) * _r) % n;
    if (_s.sign == 0) {
      return false;
    }

    return true;
  }
}
