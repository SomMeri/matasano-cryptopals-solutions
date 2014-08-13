package org.meri.matasano.utils.encryption;

import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.Xor;

public class AESCTR {

  private static final int NONCE_LENTH = 8;

  private ArrayManips arrayUtils = new ArrayManips();
  private Xor xor = new Xor();

  public byte[] decrypt(byte[] ciphertext, byte[] key) {
    return whateverCrypt(ciphertext, key);
  }

  public byte[] encrypt(byte[] plaintext, byte[] key) {
    return whateverCrypt(plaintext, key);
  }

  public byte[] edit(byte[] ciphertext, byte[] key, int offset, byte[] newtext) {
    byte[] plaintext = decrypt(ciphertext, key);
    if (offset >= plaintext.length)
      throw new IllegalStateException("Invalid offset " + offset + " the text is only " + plaintext.length + " bytes long.");

    int length = Math.min(newtext.length, ciphertext.length - offset);
    System.arraycopy(plaintext, offset, newtext, 0, length);
    
    return encrypt(plaintext, key);
  }

  private byte[] whateverCrypt(byte[] whatevertext, byte[] key) {
    AES aes = new AES(key);
    int blockLength = aes.getBlockLength();
    IncrementalNonce nonce = new IncrementalNonce(blockLength - NONCE_LENTH, 8);

    int totalBlocks = arrayUtils.countBlocks(whatevertext, blockLength);
    byte[] result = new byte[whatevertext.length];
    for (int i = 0; i < totalBlocks; i++) {
      byte[] encryptedNonce = aes.encrypt(nonce.getBytes());

      byte[] block = arrayUtils.extractBlock(whatevertext, blockLength, i);
      byte[] cipherBlock = xor.xor(block, encryptedNonce);

      arrayUtils.replaceBlockCutToFit(result, cipherBlock, i);

      nonce.increment();
    }
    return result;
  }

  public int getBlockSize() {
    return 16;
  }

}
