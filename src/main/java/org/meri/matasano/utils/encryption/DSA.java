package org.meri.matasano.utils.encryption;

import java.math.BigInteger;

import org.apache.shiro.codec.Hex;
import org.meri.matasano.utils.RandomUtils;

public class DSA {

  private RandomUtils random = new RandomUtils();
  private BigInteger x;
  private BigInteger y;
  private BigInteger p;
  private BigInteger q;
  private BigInteger g;

  public DSA(BigInteger p, BigInteger q, BigInteger g) {
    this.p = p;
    this.q = q;
    this.g = g;
    this.x = random.getPositiveBigInteger(q);
    this.y = g.modPow(x, p);
  }

  public DSA(DSAPublicKey key) {
    this.p = key.getP();
    this.q = key.getQ();
    this.g = key.getG();
    this.x = null;
    this.y = key.getY();
  }

  public DSA(DSAPublicKey publicKey, BigInteger x) {
    this(publicKey);
    this.x = x;
    if (!this.y.equals(g.modPow(x, p)))
      throw new IllegalStateException("Private public key mismatch.");
  }

  public DSASignature createSignature(byte[] message) {
    if (x == null)
      throw new IllegalStateException("This is validating-only instance.");

    BigInteger hash = hash(message);

    BigInteger k = BigInteger.ZERO;
    BigInteger r = BigInteger.ZERO;
    BigInteger s = BigInteger.ZERO;
    while (s.equals(BigInteger.ZERO)) {
      while (r.equals(BigInteger.ZERO)) {
        k = random.getPositiveBigInteger(q);
        r = g.modPow(k, p).mod(q);
      }

      BigInteger km1 = k.modInverse(q);
      s = km1.multiply(hash.add(x.multiply(r))).mod(q);
    }

    return new DSASignature(r, s);
  }

  public DSASignature createSignature_allow0(byte[] message) {
    if (x == null)
      throw new IllegalStateException("This is validating-only instance.");

    BigInteger hash = hash(message);

    BigInteger k = BigInteger.ZERO;
    BigInteger r = BigInteger.ZERO;
    BigInteger s = BigInteger.ZERO;
    while (s.equals(BigInteger.ZERO)) {
      k = random.getPositiveBigInteger(q);
      r = g.modPow(k, p).mod(q);

      BigInteger km1 = k.modInverse(q);
      s = km1.multiply(hash.add(x.multiply(r))).mod(q);
    }

    return new DSASignature(r, s);
  }

  public BigInteger hash(byte[] message) {
    String hexadecimalHash = Hex.encodeToString(SHA1.encode(message));
    return new BigInteger(hexadecimalHash, 16);
  }

  public boolean isValidSignature(byte[] message, DSASignature signature) {
    if (!isLowerPositive(signature.getR(), q) || !isLowerPositive(signature.getS(), q))
      return false;

    BigInteger w = signature.getS().modInverse(q);
    BigInteger u1 = hash(message).multiply(w).mod(q);
    BigInteger u2 = signature.getR().multiply(w).mod(q);

    BigInteger v = g.modPow(u1, p).multiply(y.modPow(u2, p)).mod(p).mod(q);
    return v.equals(signature.getR());
  }

  private boolean isLowerPositive(BigInteger s, BigInteger q) {
    if (s.compareTo(BigInteger.ZERO) <= 0)
      return false;

    if (s.compareTo(q) >= 0)
      return false;

    return true;
  }

  public DSAPublicKey getPublicKey() {
    return new DSAPublicKey(p, q, g, y);
  }

  public static class DSASignature {
    private final BigInteger r;
    private final BigInteger s;

    public DSASignature(BigInteger r, BigInteger s) {
      super();
      this.r = r;
      this.s = s;
    }

    public BigInteger getR() {
      return r;
    }

    public BigInteger getS() {
      return s;
    }

  }

  public static class DSAPublicKey {
    private final BigInteger p;
    private final BigInteger q;
    private final BigInteger g;
    private final BigInteger y;

    public DSAPublicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
      super();
      this.p = p;
      this.q = q;
      this.g = g;
      this.y = y;
    }

    public BigInteger getP() {
      return p;
    }

    public BigInteger getQ() {
      return q;
    }

    public BigInteger getG() {
      return g;
    }

    public BigInteger getY() {
      return y;
    }

  }

}
