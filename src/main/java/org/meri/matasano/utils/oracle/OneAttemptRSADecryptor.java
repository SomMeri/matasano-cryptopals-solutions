package org.meri.matasano.utils.oracle;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.meri.matasano.utils.encryption.RSA;
import org.meri.matasano.utils.encryption.RSA.RSAPublicKey;

public class OneAttemptRSADecryptor {

  private RSA rsa = new RSA();
  private Set<Integer> used = new HashSet<Integer>();

  public byte[] encrypt(byte[] plaintext) {
    return rsa.encrypt(plaintext);
  }

  public byte[] decrypt(byte[] ciphertext) {
    int hashCode = Arrays.hashCode(ciphertext);
    
    if (used.contains(hashCode))
      throw new IllegalAccessError("Message was aready decrypted.");
    
    used.add(hashCode);
    return rsa.decrypt(ciphertext);
  }

  public RSAPublicKey getPublicKey() {
    return rsa.getPublicKey();
    // TODO Auto-generated method stub
    
  }

}
