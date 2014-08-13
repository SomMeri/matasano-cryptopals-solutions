package org.meri.matasano.utils.oracle;

import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.meri.matasano.utils.encryption.AESCTR;
import org.meri.matasano.utils.encryption.CoreCipher;

public class ConstantKeyAESCTR implements EncryptingOracleCipher, CoreCipher {

  private final byte[] key;
  
  private AESCTR aesctr = new AESCTR();
  
  public ConstantKeyAESCTR() {
    RandomNumberGenerator generator = new SecureRandomNumberGenerator();
    key = generator.nextBytes(aesctr.getBlockSize()).getBytes();
  }

  public ConstantKeyAESCTR(AESCTR aescbc) {
    this();
    this.aesctr = aescbc;
  }

  public byte[] decrypt(byte[] ciphertext) {
    return aesctr.decrypt(ciphertext, key);
  }

  public byte[] encrypt(byte[] plaintext) {
    return aesctr.encrypt(plaintext, key);
  }

  public int getBlockLength() {
    return aesctr.getBlockSize();
  }

}
