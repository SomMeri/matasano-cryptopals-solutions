package org.meri.matasano.utils.oracle;

import java.math.BigInteger;

import org.meri.matasano.utils.encryption.RSA;
import org.meri.matasano.utils.encryption.RSA.RSAPublicKey;

public class LastBitRSAOracle {
  
  private final RSA rsa;

  public LastBitRSAOracle(RSA rsa) {
    super();
    this.rsa = rsa;
  }

  public boolean isEven(byte[] ciphertext) {
    byte[] decrypt = rsa.decrypt(ciphertext);
    return decrypt[decrypt.length-1] % 2==0;
  }

  public BigInteger encrypt(BigInteger plaintext) {
    return rsa.encrypt(plaintext);
  }

  public RSAPublicKey getPublicKey() {
    return rsa.getPublicKey();
  }

  public boolean isEven(BigInteger multiply) {
    return isEven(multiply.toByteArray());
  }

}
