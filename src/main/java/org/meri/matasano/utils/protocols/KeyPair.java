package org.meri.matasano.utils.protocols;

import java.math.BigInteger;

public class KeyPair {
  
  private final BigInteger privateKey;
  private final BigInteger publicKey;

  public KeyPair(BigInteger privateKey, BigInteger publicKey) {
    super();
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  public BigInteger getPrivateKey() {
    return privateKey;
  }

  public BigInteger getPublicKey() {
    return publicKey;
  }

  @Override
  public String toString() {
    return "KeyPair [privateKey=" + privateKey + ",\n publicKey=" + publicKey + "]";
  }


}
