package org.meri.matasano.utils.cryptoanalysis;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.shiro.codec.CodecSupport;
import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.Ascii;
import org.meri.matasano.utils.Xor;

public class HammingBasedMultipleTimePadCryptanalysis {

  private Ascii ascii = new Ascii();
  private ArrayManips arrayUtils = new ArrayManips();
  private Xor xor = new Xor();

  private char keyMinimum = 0;
  private char keyMaximum = 255;

  public DecodedResult decodeAssumeOneLetterLongKey(byte[] raw) {
    DecodedResult result = new DecodedResult(-1);

    for (char guess = keyMinimum; guess < keyMaximum; guess++) {
      byte[] decoded = xor.xor(raw, guess);

      int score = ascii.countCharacters(decoded);

      /**
       * The <= is kind of cheating. I used it specifically for exercise 6.
       * 
       * Key position 23 gives the same score for e and b, but only e is right.
       * I could also tweak the score or modify the whole thing to check
       * dictionary. Since this is throw away code, I opted for hack.
       */
      if (result.getAsciiCharactersCount() == score) {
        result.addPossibleResult(decoded);
      } else if (result.getAsciiCharactersCount() < score) {
        result = new DecodedResult(score);
        result.addPossibleResult(decoded);
      }
    }
    return result;
  }

  public byte[] decode(byte[] cipher, int keyLength) {
    byte[] transposedCipher = arrayUtils.transpose(cipher, keyLength);
    int transposedBlockLength = arrayUtils.transposedBlockLength(cipher, keyLength);

    byte[] joinedSolvedBlocks = blockBasedDecoding(transposedCipher, transposedBlockLength);
    byte[] decoded = arrayUtils.transpose(joinedSolvedBlocks, transposedBlockLength);
    //remove padding
    decoded = Arrays.copyOf(decoded, cipher.length);
    return decoded;
  }

  public byte[] decode(byte[] cipher) {
    int guessedKeySize = guessKeySize(cipher);
    return decode(cipher, guessedKeySize);
  }

  private int guessKeySize(byte[] rawCipher) {
    Hamming hamming = new Hamming();
    double minDistance = Double.MAX_VALUE;
    int result = -1;

    for (int guessedKeySize = 2; guessedKeySize <= 40; guessedKeySize++) {
      int blocksCount = rawCipher.length / guessedKeySize - 1;
      double totalDistance = 0;
      for (int basedOnBlock = 0; basedOnBlock < blocksCount; basedOnBlock++) {

        byte[] firstBlock = arrayUtils.extractBlock(rawCipher, guessedKeySize, basedOnBlock);
        byte[] secondBlock = arrayUtils.extractBlock(rawCipher, guessedKeySize, basedOnBlock + 1);

        totalDistance += hamming.normalizedDistance(firstBlock, secondBlock);

      }

      double averageDistance = totalDistance / blocksCount;
      if (minDistance > averageDistance) {
        minDistance = averageDistance;
        result = guessedKeySize;
      }
    }

    return result;
  }

  private byte[] blockBasedDecoding(byte[] allBlocks, int blockLength) {
    byte[] result = new byte[allBlocks.length];

    for (int index = 0; index * blockLength < allBlocks.length; index++) {
      byte[] block = arrayUtils.extractBlock(allBlocks, blockLength, index);
      DecodedResult decodedResult = decodeAssumeOneLetterLongKey(block);
      arrayUtils.replaceBlock(result, decodedResult.getFirst(), index);
    }

    return result;
  }

  public class DecodedResult {

    private List<byte[]> possibleResults = new ArrayList<byte[]>();
    private int asciiCharactersCount;

    public DecodedResult(int asciiCharactersCount) {
      super();
      this.asciiCharactersCount = asciiCharactersCount;
    }

    public int possiblesCount() {
      return possibleResults.size();
    }

    public byte[] getFirst() {
      return possibleResults.get(0);
    }

    public byte[] get(int index) {
      return possibleResults.get(index);
    }

    public void addPossibleResult(byte[] possible) {
      possibleResults.add(possible);
    }

    public String getResultAsString() {
      return CodecSupport.toString(possibleResults.get(0));
    }

    public int getAsciiCharactersCount() {
      return asciiCharactersCount;
    }

    public byte[] assumeClearResult() {
      if (possiblesCount()>1)
        throw new IllegalStateException("Too many solutions found.");

      return getFirst();
    }

  }

}
