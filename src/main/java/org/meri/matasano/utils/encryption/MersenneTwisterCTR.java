package org.meri.matasano.utils.encryption;

import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.Xor;

public class MersenneTwisterCTR {
  
  private ArrayManips arrayUtils = new ArrayManips();
  private Xor xor = new Xor();

  public byte[] decrypt(byte[] ciphertext, int key) {
    return whateverCrypt(ciphertext, key);
  }

  public byte[] encrypt(byte[] plaintext, int key) {
    return whateverCrypt(plaintext, key);
  }

  private byte[] whateverCrypt(byte[] ciphertext, int key) {
    MerseneTwisterRandom random = new MerseneTwisterRandom(key);
    byte[] expandedKey = arrayUtils.castToBytes(random.getInts(ciphertext.length));

    return xor.xor(expandedKey, ciphertext);
  }

}
