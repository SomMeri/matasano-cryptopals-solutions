package org.meri.matasano.utils.encryption;


public class ShortKeyMersenneTwisterCTR extends MersenneTwisterCTR{
  
  public static final int RELEVANT_KEY_BITS = 0xffff;

  public byte[] decrypt(byte[] ciphertext, int key) {
    return super.decrypt(ciphertext, key & RELEVANT_KEY_BITS);
  }

  public byte[] encrypt(byte[] plaintext, int key) {
    return super.encrypt(plaintext, key & RELEVANT_KEY_BITS);
  }

}
