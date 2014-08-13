package org.meri.matasano;

import java.math.BigDecimal;
import java.math.BigInteger;

import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.cryptoanalysis.Bleichenbacher98;
import org.meri.matasano.utils.cryptoanalysis.Bleichenbacher98_limited;
import org.meri.matasano.utils.cryptoanalysis.IBleichenbacher98;
import org.meri.matasano.utils.encryption.DSA;
import org.meri.matasano.utils.encryption.DSA.DSAPublicKey;
import org.meri.matasano.utils.encryption.DSA.DSASignature;
import org.meri.matasano.utils.encryption.RSA.RSAPublicKey;
import org.meri.matasano.utils.encryption.SHA1;
import org.meri.matasano.utils.oracle.LastBitRSAOracle;
import org.meri.matasano.utils.oracle.OneAttemptRSADecryptor;

public class Set6 {

  private static final BigInteger THREE = BigInteger.valueOf(3);
  private static final BigInteger TWO = BigInteger.valueOf(2);
  private ArrayManips manips = new ArrayManips();

  /**
   * Exercise 41
   */
  public byte[] recoverMessage(OneAttemptRSADecryptor decriptor, byte[] ciphertext) {
    RSAPublicKey publicKey = decriptor.getPublicKey();
    BigInteger N = publicKey.getN();
    BigInteger e = publicKey.getE();

    BigInteger cipher = new BigInteger(ciphertext);
    BigInteger modifiedCipher = cipher.multiply(TWO.modPow(e, N)).mod(N);

    byte[] modifiedPlaintext = decriptor.decrypt(modifiedCipher.toByteArray());

    BigInteger modified = new BigInteger(modifiedPlaintext);
    BigInteger plain = half(modified, N);

    return plain.toByteArray();
  }

  /**
   * Exercise 42
   * 
   * I took the easy second option.
   */
  public byte[] forgeRSASignature(byte[] forgedMessage, RSAPublicKey publicKey) {
    if (!publicKey.getE().equals(THREE))
      throw new IllegalArgumentException("Attack is valid only for e=3.");

    byte[] padding = new byte[] { 0, 1, (byte) 0xff, 0 };
    byte[] forgedHash = SHA1.encode(forgedMessage);

    byte[] paddedHash = manips.join(padding, forgedHash);
    byte[] paddedMessageMinimum = new byte[getRsaBlockLength(publicKey)];
    System.arraycopy(paddedHash, 0, paddedMessageMinimum, 0, paddedHash.length);

    byte[] paddedMessageMaximum = manips.createInitializedArray(getRsaBlockLength(publicKey), 255);
    System.arraycopy(paddedHash, 0, paddedMessageMaximum, 0, paddedHash.length);

    BigInteger cubeRoot = cubeRootBetween(new BigInteger(paddedMessageMinimum), new BigInteger(paddedMessageMaximum));
    return cubeRoot.toByteArray();
  }

  private BigInteger cubeRootBetween(BigInteger minimum, BigInteger maximum) {
    BigInteger min = TWO;
    BigInteger max = minimum;
    BigInteger current = min.divide(THREE);
    while (!(lessThen(minimum, current.pow(3)) && lessThen(current.pow(3), maximum))) {
      if (lessThen(current.pow(3), minimum)) {
        min = current;
        current = min.add(max.add(current.negate()).divide(TWO));
      } else {
        max = current;
        current = min.add(max.add(current.negate()).divide(TWO));
      }
    }

    return current;
  }

  private boolean lessThen(BigInteger current, BigInteger minimum) {
    return current.compareTo(minimum) < 0;
  }

  private int getRsaBlockLength(RSAPublicKey publicKey) {
    return publicKey.getN().toByteArray().length - 1;
  }

  public BigInteger getDsaPrivateKey(byte[] message, DSASignature signature, DSAPublicKey key) {
    BigInteger k = findK(signature, key);
    return getDsaPrivateKey(message, signature, key, k);
  }

  private BigInteger getDsaPrivateKey(byte[] message, DSASignature signature, DSAPublicKey key, BigInteger k) {
    BigInteger s = signature.getS();
    BigInteger q = key.getQ();

    DSA dsa = new DSA(key);
    BigInteger hash = dsa.hash(message);

    BigInteger up = s.multiply(k).add(hash.negate()).mod(q);
    BigInteger down = signature.getR().modInverse(q);

    return up.multiply(down).mod(q);
  }

  private BigInteger findK(DSASignature signature, DSAPublicKey key) {
    // we have intelligence saying that k is probably higher then 16574 
    // I did this to speed up test
    int speedKLookup = 16574;

    BigInteger g = key.getG();
    BigInteger p = key.getP();
    BigInteger q = key.getQ();

    BigInteger r = signature.getR();
    for (int k = speedKLookup; k < 65536; k++) {
      BigInteger guessedR = g.modPow(BigInteger.valueOf(k), p).mod(q);
      if (guessedR.equals(r))
        return BigInteger.valueOf(k);
    }
    for (int k = 0; k < speedKLookup; k++) {
      BigInteger guessedR = g.modPow(BigInteger.valueOf(k), p).mod(q);
      if (guessedR.equals(r))
        return BigInteger.valueOf(k);
    }
    throw new IllegalStateException("k not found");
  }

  public BigInteger getDsaPrivateKey(byte[] message1, DSASignature signature1, byte[] message2, DSASignature signature2, DSAPublicKey publicKey) {
    DSA dsa = new DSA(publicKey);
    BigInteger m1 = dsa.hash(message1);
    BigInteger m2 = dsa.hash(message2);

    BigInteger nominator = m1.add(m2.negate()).mod(publicKey.getQ());
    BigInteger denominator = signature1.getS().add(signature2.getS().negate()).mod(publicKey.getQ());
    BigInteger k = nominator.multiply(denominator.modInverse(publicKey.getQ())).mod(publicKey.getQ());

    return getDsaPrivateKey(message2, signature2, publicKey, k);
  }

  public byte[] decryptRsa(byte[] ciphertext, LastBitRSAOracle oracle, boolean hollywood) {
    BigInteger n = oracle.getPublicKey().getN();
    BigInteger cipher = new BigInteger(ciphertext);

    BigDecimal minimum = BigDecimal.ZERO;
    BigDecimal maximum = new BigDecimal(n);//n.add(BigInteger.ONE.negate());
    BigInteger encryptedMultiplier = oracle.encrypt(TWO);
    while (0 > BigDecimal.valueOf(0.5).compareTo(maximum.add(minimum.negate()))) {
      cipher = cipher.multiply(encryptedMultiplier).mod(n);
      BigDecimal half = minimum.add(maximum).divide(BigDecimal.valueOf(2));
      boolean even = oracle.isEven(cipher);
      if (even) {
        maximum = half;
      } else {
        minimum = half;
      }
      if (hollywood) {
        System.out.println(maximum);
        System.out.println(new String(maximum.toBigInteger().toByteArray()));
      }
    }

    return maximum.toBigInteger().toByteArray();
  }

  private BigInteger half(BigInteger number, BigInteger modulus) {
    return number.multiply(TWO.modInverse(modulus)).mod(modulus);
  }

  public IBleichenbacher98 createLimitedBleichenbacher() {
    return new Bleichenbacher98_limited();
  }

  public IBleichenbacher98 createBleichenbacher() {
    return new Bleichenbacher98();
  }

}
