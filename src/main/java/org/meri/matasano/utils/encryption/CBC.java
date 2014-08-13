package org.meri.matasano.utils.encryption;

import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.Xor;

public class CBC {

  private ArrayManips arrayUtils = new ArrayManips();
  private Xor xor = new Xor();

  public byte[] encrypt(byte[] plaintext, byte[] iv, CoreCipher coreCipher) {
    byte[] result = new byte[plaintext.length];
    int blockLength = coreCipher.getBlockLength();
    int totalBlocks = arrayUtils.countBlocks(plaintext, blockLength);

    byte[] previousBlock = iv;
    for (int i = 0; i < totalBlocks; i++) {
      byte[] block = arrayUtils.extractBlock(plaintext, blockLength, i);
      byte[] blockToEncrypt = xor.xor(previousBlock, block);

      previousBlock = coreCipher.encrypt(blockToEncrypt);
      arrayUtils.replaceBlock(result, previousBlock, i);
    }

    return result;
  }

  public byte[] decrypt(byte[] ciphertext, byte[] iv, CoreCipher coreCipher) {
    byte[] result = new byte[ciphertext.length];
    int blockLength = coreCipher.getBlockLength();
    int lastBlockIdx = arrayUtils.countBlocks(ciphertext, blockLength) - 1;

    byte[] currentCipherBlock = arrayUtils.extractBlock(ciphertext, blockLength, lastBlockIdx);
    for (int idx = lastBlockIdx; idx >= 0; idx--) {
      byte[] decrypt = coreCipher.decrypt(currentCipherBlock);
      byte[] previousCipherBlock = idx == 0 ? iv : arrayUtils.extractBlock(ciphertext, blockLength, idx - 1);
      byte[] plaintextBlock = xor.xor(decrypt, previousCipherBlock);
      arrayUtils.replaceBlock(result, plaintextBlock, idx);
      currentCipherBlock = previousCipherBlock;
    }

    return result;
  }

}
