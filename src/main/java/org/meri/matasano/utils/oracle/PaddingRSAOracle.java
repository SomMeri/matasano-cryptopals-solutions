package org.meri.matasano.utils.oracle;

import java.math.BigInteger;

import org.meri.matasano.utils.encryption.RSA;
import org.meri.matasano.utils.encryption.RSA.RSAPublicKey;

public class PaddingRSAOracle {
  
  private final RSA rsa;
  private int plainLength;

  public PaddingRSAOracle(RSA rsa) {
    super();
    this.rsa = rsa;
    this.plainLength = rsa.getPublicKey().getN().toByteArray().length;
  }

  protected boolean hasValidPadding(byte[] ciphertext) {
    byte[] plaintext = rsa.decrypt(ciphertext);
    return checkPadding(plaintext);
  }

  private boolean checkPadding(byte[] plaintext) {
    if(plaintext.length<plainLength-1)
      return false;
    
    return plaintext[0]==2;
  }

  protected BigInteger encrypt(BigInteger plaintext) {
    return rsa.encrypt(plaintext);
  }

  public RSAPublicKey getPublicKey() {
    return rsa.getPublicKey();
  }

  public boolean hasValidPadding(BigInteger ciphertext) {
    return hasValidPadding(ciphertext.toByteArray());
  }

}
