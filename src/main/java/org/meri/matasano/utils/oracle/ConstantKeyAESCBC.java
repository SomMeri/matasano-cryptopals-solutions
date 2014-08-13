package org.meri.matasano.utils.oracle;

import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.meri.matasano.utils.encryption.AESCBC;
import org.meri.matasano.utils.encryption.CoreCipher;

public class ConstantKeyAESCBC implements EncryptingOracleCipher, CoreCipher {

  private final byte[] key;
  private final byte[] iv;
  
  private AESCBC aescbc = new AESCBC();
  
  public ConstantKeyAESCBC() {
    RandomNumberGenerator generator = new SecureRandomNumberGenerator();
    key = generator.nextBytes(aescbc.getBlockSize()).getBytes();
    iv = generator.nextBytes(aescbc.getBlockSize()).getBytes();
  }
  
  public ConstantKeyAESCBC(byte[] key, byte[] iv) {
    this.key = key;
    this.iv = iv;
  }


  public ConstantKeyAESCBC(AESCBC aescbc) {
    this();
    this.aescbc = aescbc;
  }

  public ConstantKeyAESCBC(byte[] key) {
    this.key = key;
    RandomNumberGenerator generator = new SecureRandomNumberGenerator();
    iv = generator.nextBytes(aescbc.getBlockSize()).getBytes();
  }

  public byte[] decrypt(byte[] ciphertext) {
    return aescbc.decrypt(ciphertext, key, iv);
  }

  public byte[] encrypt(byte[] plaintext) {
    return aescbc.encrypt(plaintext, key, iv);
  }

  public int getBlockLength() {
    return aescbc.getBlockSize();
  }

  protected byte[] getIv() {
    return iv;
  }
  
  protected byte[] getKey() {
    return key;
  }

  public int getBlockSize() {
    return aescbc.getBlockSize();
  }

  

}
