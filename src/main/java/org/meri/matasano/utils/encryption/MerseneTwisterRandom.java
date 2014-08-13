package org.meri.matasano.utils.encryption;

import java.util.Arrays;

/**
 * Mersene Twister implementation as found on wiki.  
 *
 */
public class MerseneTwisterRandom {

  public static final int BITS_0_30 = 0x7fffffff;
  public static final int BIT_31 = 0x80000000;

  private static final int INIT_FACTOR = 1812433253;
  public static final int GENERATING_FACTOR = 0x9908b0df;
  public static final int FINAL_FACTOR_1 = 0x9d2c5680;
  public static final int FINAL_FACTOR_2 = 0xefc60000;

  public static final int MT_LENGTH = 624;

  private int[] MT = new int[MT_LENGTH];
  private int index = 0;

  public MerseneTwisterRandom() {

  }

  public MerseneTwisterRandom(int seed) {
    setSeed(seed);
  }

  public MerseneTwisterRandom(int[] initial_mt) {
    if (initial_mt.length!=MT_LENGTH)
      throw new IllegalArgumentException("Length of input array must be "+MT_LENGTH);
    
    MT = Arrays.copyOf(initial_mt, initial_mt.length);
  }

  public void setSeed(int seed) {
    MT[0] = seed;
    for (int i = 1; i < MT_LENGTH; i++) {
      MT[i] = INIT_FACTOR * (MT[i - 1] ^ (MT[i - 1] >>> 30)) + i;
    }
    
    generateMT();
  }

  public int[] getInts(int length) {
    int[] result = new int[length];
    for (int i = 0; i < result.length; i++) {
      result[i] = getRandomInt();
    }
    return result;
  }

  public int getRandomInt() {
    int result = MT[index];
    result ^= (result >>> 11);
    result ^= (result << 7) & FINAL_FACTOR_1;
    result ^= (result << 15) & FINAL_FACTOR_2;
    result ^= (result >>> 18);

    index = (index + 1) % MT_LENGTH;
    if (index == 0) {
      generateMT(); 
    }
    return result;
  }

  private void generateMT() {
    for (int i = 0; i < MT_LENGTH; i++) {
      int nextI = (i + 1) % MT_LENGTH;
      int y = (MT[i] & BIT_31) + (MT[nextI] & BITS_0_30);

      MT[i] = MT[(i + 397) % MT_LENGTH] ^ (y >>> 1);
      if (isOdd(y)) {
        MT[i] = MT[i] ^ GENERATING_FACTOR;
      }
    }

  }

  private boolean isOdd(int number) {
    return (number << 31) !=0;
  }
}
