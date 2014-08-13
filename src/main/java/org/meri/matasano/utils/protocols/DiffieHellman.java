package org.meri.matasano.utils.protocols;

import java.math.BigInteger;
import java.util.Arrays;

import org.meri.matasano.utils.RandomUtils;
import org.meri.matasano.utils.encryption.SHA1;

public class DiffieHellman {
  
  private final RandomUtils randomUtils = new RandomUtils();

  private final BigInteger p;
  private final BigInteger g;

  public DiffieHellman(int p, int g) {
    super();
    this.p = BigInteger.valueOf(p);
    this.g = BigInteger.valueOf(g);
  }

  public DiffieHellman(BigInteger p, BigInteger g) {
    super();
    this.p = p;
    this.g = g;
  }

  public KeyPair generateKeyPair() {
    BigInteger privateKey = randomUtils.getPositiveBigInteger(p);
    BigInteger publicKey = g.modPow(privateKey, p);
    
    return new KeyPair(privateKey, publicKey);
  }

  public byte[] sessionKeyWith(KeyPair aA, BigInteger otherPublicKey) {
    BigInteger s = otherPublicKey.modPow(aA.getPrivateKey(), p);
    return convertToKey(s);
  }

  public byte[] convertToKey(BigInteger s) {
    return Arrays.copyOf(SHA1.encode(s.toByteArray()), 16);
  }

  public BigInteger getP() {
    return p;
  }

  public BigInteger getG() {
    return g;
  }
}
