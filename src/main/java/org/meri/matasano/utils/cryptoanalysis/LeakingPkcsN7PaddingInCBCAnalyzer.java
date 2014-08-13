package org.meri.matasano.utils.cryptoanalysis;

import java.util.Arrays;

import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.Ascii;
import org.meri.matasano.utils.encryption.PkcsN7Padding;
import org.meri.matasano.utils.oracle.PaddingValidatingOracle;

public class LeakingPkcsN7PaddingInCBCAnalyzer {
  
  private PkcsN7Padding padding = new PkcsN7Padding();
  private ArrayManips arrayUtils = new ArrayManips();
  private Ascii ascii = new Ascii();
  
  private final PaddingValidatingOracle oracle;
  private final int blockLength;

  public LeakingPkcsN7PaddingInCBCAnalyzer(PaddingValidatingOracle oracle) {
    this.oracle = oracle;
    this.blockLength = oracle.getBlockLength();
  }

  public byte[] decryptLeakingPkcsN7Padding(byte[] ciphertext) {
    int numOfBlocks = arrayUtils.countBlocks(ciphertext, blockLength);

    byte[] result = new byte[0];
    for (int blockNumber = numOfBlocks - 1; blockNumber > 0; blockNumber--) {
      byte[] blockResult = decryptBlock(ciphertext, blockNumber);
      result = arrayUtils.join(blockResult, result);
    }
    return padding.removePadding(result);
  }


  private byte[] decryptBlock(byte[] fullCiphertext, int blockNumber) {
    int modifyBlock = blockNumber - 1;
    byte[] ciphertext = Arrays.copyOf(fullCiphertext, blockLength * (blockNumber + 1));
    byte[] result = new byte[blockLength];
    byte[] originalVersionOfModifiedBlock = arrayUtils.extractBlock(ciphertext, blockLength, modifyBlock);

    for (int inBlockIdx = blockLength - 1; inBlockIdx >= 0; inBlockIdx--) {
      byte padding = (byte)(blockLength - inBlockIdx);
      int attackedByte = modifyBlock * blockLength + inBlockIdx;
      // prepare known bytes to generate the right padding 
      for (int knownByte = inBlockIdx + 1; knownByte < blockLength; knownByte++) {
        ciphertext[modifyBlock * blockLength + knownByte] = (byte) (padding ^ result[knownByte] ^ originalVersionOfModifiedBlock[knownByte]);
      }

      // find the right byte
      byte rightByte = iterateToCrackByte(ciphertext, attackedByte, padding);
      // calculate plaintext byte 
      result[inBlockIdx] = rightByte;
    }
    return result;
  }

  private byte iterateToCrackByte(byte[] ciphertext, int attackedByte, byte expectedPadding) {
    byte originalByte = ciphertext[attackedByte];
    
    for (int guess = Byte.MIN_VALUE; guess <= Byte.MAX_VALUE; guess++) {
      if (guess != originalByte) {
        ciphertext[attackedByte] = (byte)guess;
        if (oracle.validatePadding(ciphertext)) {
          byte guessedToResult = (byte) (guess ^ originalByte ^ expectedPadding);
          boolean isAcceptable = isPossiblePlaintext(guessedToResult);
          
          return isAcceptable? guessedToResult : expectedPadding;
        }
      }
    }
    // encryption left the byte unchanged
    return expectedPadding;
  }

  private boolean isPossiblePlaintext(byte guessedToResult) {
    return (guessedToResult>0 && guessedToResult <= blockLength) || ascii.isCookieCharacter(guessedToResult);
  }

}
