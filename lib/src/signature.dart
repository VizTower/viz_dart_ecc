import 'dart:typed_data';
import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';
import "package:pointycastle/api.dart" show PublicKeyParameter;
import 'package:pointycastle/ecc/api.dart'
    show ECPublicKey, ECSignature, ECPoint;
import "package:pointycastle/signers/ecdsa_signer.dart";
import 'package:pointycastle/macs/hmac.dart';
import "package:pointycastle/digests/sha256.dart";
import 'package:pointycastle/src/utils.dart';

import './exception.dart';
import './key.dart';
import './key_base.dart';

/// VIZ Signature
class VIZSignature extends VIZKey {
  int i;
  ECSignature ecSig;

  /// Default constructor from i, r, s
  VIZSignature(this.i, BigInt r, BigInt s) {
    this.ecSig = ECSignature(r, s);
  }

  /// Construct VIZ signature from buffer
  VIZSignature.fromBuffer(Uint8List buffer) {
    if (buffer.lengthInBytes != 65) {
      throw InvalidKey(
          'Invalid signature length, got: ${buffer.lengthInBytes}');
    }

    i = buffer.first;

    if (i - 27 != i - 27 & 7) {
      throw InvalidKey('Invalid signature parameter');
    }

    BigInt r = decodeBigInt(buffer.sublist(1, 33));
    BigInt s = decodeBigInt(buffer.sublist(33, 65));
    this.ecSig = ECSignature(r, s);
  }

  /// Construct VIZ signature from string
  factory VIZSignature.fromString(String signatureStr) {
    Uint8List key = hex.decode(signatureStr);
    return VIZSignature.fromBuffer(key);
  }

  /// Verify the signature of the string raw data
  bool verify(String rawData, VIZPublicKey publicKey) {
    Digest d = sha256.convert(utf8.encode(rawData));

    return verifyHash(d.bytes, publicKey);
  }

  /// Verify the signature from in SHA256 hashed raw data
  bool verifyHash(Uint8List sha256Data, VIZPublicKey publicKey) {
    ECPoint q = publicKey.q;
    final signer = ECDSASigner(null, HMac(SHA256Digest(), 64));
    signer.init(false, PublicKeyParameter(ECPublicKey(q, VIZKey.secp256k1)));

    return signer.verifySignature(sha256Data, this.ecSig);
  }

  String toString() {
    List<int> b = List();
    b.add(i);
    b.addAll(encodeBigInt(this.ecSig.r));
    b.addAll(encodeBigInt(this.ecSig.s));

    Uint8List buffer = Uint8List.fromList(b);
    return hex.encode(buffer);
  }

  /// ECSignature to DER format bytes
  static Uint8List ecSigToDER(ECSignature ecSig) {
    List<int> r = VIZKey.toSigned(encodeBigInt(ecSig.r));
    List<int> s = VIZKey.toSigned(encodeBigInt(ecSig.s));

    List<int> b = List();
    b.add(0x02);
    b.add(r.length);
    b.addAll(r);

    b.add(0x02);
    b.add(s.length);
    b.addAll(s);

    b.insert(0, b.length);
    b.insert(0, 0x30);

    return Uint8List.fromList(b);
  }

  /// Find the public key recovery factor
  static int calcPubKeyRecoveryParam(
      BigInt e, ECSignature ecSig, VIZPublicKey publicKey) {
    for (int i = 0; i < 4; i++) {
      ECPoint Qprime = recoverPubKey(e, ecSig, i);
      if (Qprime == publicKey.q) {
        return i;
      }
    }
    throw 'Unable to find valid recovery factor';
  }

  /// Recovery VIZ public key from ECSignature
  static ECPoint recoverPubKey(BigInt e, ECSignature ecSig, int i) {
    BigInt n = VIZKey.secp256k1.n;
    ECPoint G = VIZKey.secp256k1.G;

    BigInt r = ecSig.r;
    BigInt s = ecSig.s;

    // A set LSB signifies that the y-coordinate is odd
    int isYOdd = i & 1;

    // The more significant bit specifies whether we should use the
    // first or second candidate key.
    int isSecondKey = i >> 1;

    // 1.1 Let x = r + jn
    BigInt x = isSecondKey > 0 ? r + n : r;
    ECPoint R = VIZKey.secp256k1.curve.decompressPoint(isYOdd, x);
    ECPoint nR = R * n;
    if (!nR.isInfinity) {
      throw 'nR is not a valid curve point';
    }

    BigInt eNeg = (-e) % n;
    BigInt rInv = r.modInverse(n);

    ECPoint Q = (R * s + G * eNeg) * rInv;
    return Q;
  }
}
