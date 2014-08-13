package org.meri.matasano.utils.oracle;

import java.util.Arrays;

import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.encryption.AESCBC;

public class IVInCiphertextConstantKeyAESCBC extends ConstantKeyAESCBC {
  
  private final ArrayManips arrayManips = new ArrayManips();

  private AESCBC aescbc = new AESCBC();
  
  public IVInCiphertextConstantKeyAESCBC() {
  }

  public IVInCiphertextConstantKeyAESCBC(byte[] key) {
    super(key);
  }

  public IVInCiphertextConstantKeyAESCBC(AESCBC aescbc) {
    this();
    this.aescbc = aescbc;
  }

  public byte[] decrypt(byte[] ciphertext) {
    byte[] cleanCiphertext = Arrays.copyOfRange(ciphertext, getBlockLength(), ciphertext.length); 
    byte[] iv = Arrays.copyOfRange(ciphertext, 0, getBlockLength());
    
    return aescbc.decrypt(cleanCiphertext, getKey(), iv);
  }

  public byte[] encrypt(byte[] plaintext) {
    byte[] iv = getIv();
    byte[] ciphertext = aescbc.encrypt(plaintext, getKey(), iv);
    return arrayManips.join(iv, ciphertext);
  }

  public int getBlockLength() {
    return aescbc.getBlockSize();
  }
  
}
