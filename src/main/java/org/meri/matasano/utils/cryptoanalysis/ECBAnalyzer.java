package org.meri.matasano.utils.cryptoanalysis;

import java.util.Arrays;
import java.util.List;

import org.apache.shiro.codec.Hex;
import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.cryptoanalysis.ECBAnalyzer.BlockInfo;
import org.meri.matasano.utils.oracle.EncryptingOracleCipher;

public class ECBAnalyzer {

  private ArrayManips arrayUtils = new ArrayManips();
  
  public String detectEcb(List<String> hexCiphers, int blockLength) {
    int maxMatches = -1;
    String result = null;
    for (String cipher : hexCiphers) {
      int matches = countBlockMatches(Hex.decode(cipher), blockLength);
      if (matches>maxMatches) {
        maxMatches = matches;
        result = cipher;
      }
    }
    return result;
  }
  
  public boolean isECBEncryption(EncryptingOracleCipher cipher, int assumeBlockSize) {
    byte[] plaintext = constructECBDetectingPlaintext(assumeBlockSize);
    return isPossibleECB(cipher.encrypt(plaintext), assumeBlockSize);
  }
  
  private boolean isPossibleECB(byte[] cipher, int blockLength) {
    return 0<countBlockMatches(cipher, blockLength);
  }

  private byte[] constructECBDetectingPlaintext(int blockSize) {
    byte[] plaintext = new byte[blockSize*3];
    Arrays.fill(plaintext, (byte) 1);
    return plaintext;
  }

  public int countBlockMatches(byte[] cipher, int blockLength) {
    int blocksCount = cipher.length/blockLength;
    int matches = 0;
    
    for (int index=0; index < blocksCount; index++) {
      byte[] block = arrayUtils.extractBlock(cipher, blockLength, index);
      for (int j = index+1; j< blocksCount; j++) {
        byte[] other = arrayUtils.extractBlock(cipher, blockLength, j);
        if (Arrays.equals(block, other))
          matches++;
      }
    }

    return matches;
  }

  public int discoverBlockSize(EncryptingOracleCipher server) {
    return discoverBlockSizeInfo(server).getBlockLength();
  }

  public BlockInfo discoverBlockSizeInfo(EncryptingOracleCipher server) {
    int plaintextSize = 0;
    byte[] smaller = new byte[plaintextSize];
    int smallerLenth = server.encrypt(smaller).length;
    
    int longerLength = smallerLenth;
    while(longerLength == smallerLenth) {
      plaintextSize++;
      byte[] longer = new byte[plaintextSize];
      longerLength = server.encrypt(longer).length;
    }
    
    return new BlockInfo(plaintextSize, longerLength - smallerLenth);
  }
  
  public byte[] decryptServerAddedSuffix(EncryptingOracleCipher server) {
    BlockInfo blockInfo = discoverBlockSizeInfo(server);
    int blockLength = blockInfo.getBlockLength();

    if (!isECBEncryption(server, blockLength)) {
      throw new IllegalArgumentException("Server is not in ECB mode. Unable to continue.");
    }

    /**
     * I had trouble to understand how exactly should I break the cipher. In
     * case this is different attack, I apologize.
     */
    SuffixCrackingAlgorithm algorithm = new SuffixCrackingAlgorithm();
    return algorithm.decrypt(server, blockInfo);
  }

  public class BlockInfo {
    
    private final int inputSizeToGetFullPadding;
    private final int blockLength;
    
    public BlockInfo(int inputSizeToGetFullPadding, int blockLength) {
      super();
      this.inputSizeToGetFullPadding = inputSizeToGetFullPadding;
      this.blockLength = blockLength;
    }

    public int getInputSizeToGetFullPadding() {
      return inputSizeToGetFullPadding;
    }

    public int getBlockLength() {
      return blockLength;
    }
    
    
  }
}

class SuffixCrackingAlgorithm {
  
  private ArrayManips arrayUtils = new ArrayManips();
  
  public byte[] decrypt(EncryptingOracleCipher server, BlockInfo blockInfo) {
    int blockLength = blockInfo.getBlockLength();
    int exactBlockPrefixLength = blockInfo.getInputSizeToGetFullPadding();

    byte[] input = new byte[exactBlockPrefixLength + 1];
    byte[] initialInput = input;
    byte[] output = server.encrypt(input);
    int blockToExtract = arrayUtils.countBlocks(output, blockLength) - 1;
    byte[] expectedBlockCiphertext = arrayUtils.extractBlock(output, blockLength, blockToExtract);

    byte[] knownSuffix = new byte[0];

    // the condition will check whether I'm already cracking my own message 
    while (knownSuffix.length==0 || !Arrays.equals(initialInput, arrayUtils.extractBlock(knownSuffix, initialInput.length, 0))) {
      byte[] dictionaryentry = composeDictionaryEntry(knownSuffix, blockLength);
      byte theLetter = whichFirstByteGets(server, dictionaryentry, expectedBlockCiphertext);
      
      knownSuffix = arrayUtils.join(new byte[] { theLetter }, knownSuffix);
      input = new byte[input.length + 1];
      output = server.encrypt(input);
      expectedBlockCiphertext = arrayUtils.extractBlock(output, blockLength, blockToExtract);
    }

    // the beginning contains my own message, cut that out 
    knownSuffix = Arrays.copyOfRange(knownSuffix, initialInput.length, knownSuffix.length);
    return knownSuffix;
  }

  private byte[] composeDictionaryEntry(byte[] knownSuffix, int blockLength) {
    byte[] dictionaryentry = new byte[blockLength];
    System.arraycopy(knownSuffix, 0, dictionaryentry, 1, Math.min(knownSuffix.length, dictionaryentry.length - 1));

    if (knownSuffix.length > blockLength)
      return dictionaryentry;

    int from = Math.min(knownSuffix.length+1, blockLength);
    Arrays.fill(dictionaryentry, from, blockLength, (byte) (blockLength - knownSuffix.length - 1));
    return dictionaryentry;
  }

  private byte whichFirstByteGets(EncryptingOracleCipher server, byte[] dictionaryentry, byte[] expectedCiphertext) {
    for (byte guess = Byte.MIN_VALUE; guess < Byte.MAX_VALUE; guess++) {
      dictionaryentry[0] = guess;
      byte[] translation = arrayUtils.extractBlock(server.encrypt(dictionaryentry), expectedCiphertext.length, 0);
      if (Arrays.equals(translation, expectedCiphertext))
        return guess;
    }

    throw new IllegalStateException("Something wrong, no match found.");
  }

}
