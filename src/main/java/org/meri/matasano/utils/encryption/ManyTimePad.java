package org.meri.matasano.utils.encryption;

import org.meri.matasano.utils.Xor;

public class ManyTimePad implements CoreCipher {
  
  private Xor xor = new Xor();
  private final byte[] key;

  public ManyTimePad(byte[] key) {
    this.key = key;
  }

  public byte[] encrypt(byte[] plaintext) {
    return xor.xor(plaintext, key);
  }

  public byte[] decrypt(byte[] ciphertext) {
    return xor.xor(ciphertext, key);
  }

  public int getBlockLength() {
    return key.length;
  }
}
