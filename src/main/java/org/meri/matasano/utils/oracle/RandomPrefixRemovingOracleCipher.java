package org.meri.matasano.utils.oracle;

import java.util.Arrays;

import org.meri.matasano.utils.ArrayManips;

public class RandomPrefixRemovingOracleCipher implements EncryptingOracleCipher {

  private ArrayManips arrayManips = new ArrayManips();

  private EncryptingOracleCipher originalServer;
  private final byte[] signature;
  private int blockSize;
  
  public RandomPrefixRemovingOracleCipher(EncryptingOracleCipher originalServer, int blockSize) {
    this.originalServer = originalServer;
    this.blockSize = blockSize;
    signature = new byte[blockSize*3];
    Arrays.fill(signature, (byte)1);
  }

  public byte[] encrypt(byte[] plaintext) {
    plaintext = arrayManips.join(signature, plaintext);
    byte[] encrypt = originalServer.encrypt(plaintext);
    
    int signatureBlock = findFirstSignatureBlock(encrypt);
    while (signatureBlock==-1) {
      encrypt = originalServer.encrypt(plaintext);
      signatureBlock = findFirstSignatureBlock(encrypt);
    }

    return Arrays.copyOfRange(encrypt, blockSize*(signatureBlock+3), encrypt.length); 
  }

  private int findFirstSignatureBlock(byte[] encrypt) {
    int blocks = arrayManips.countBlocks(encrypt, blockSize);
    int idx = -1;
    while (idx < blocks - 3) {
      idx++;
      byte[] first = arrayManips.extractBlock(encrypt, blockSize, idx);
      byte[] second = arrayManips.extractBlock(encrypt, blockSize, idx+1);
      if (Arrays.equals(first, second)) {
        byte[] third = arrayManips.extractBlock(encrypt, blockSize, idx+2);
        if (Arrays.equals(second, third)) {
          return idx;
        }
      }
    }
    
    return -1;
  }
};
