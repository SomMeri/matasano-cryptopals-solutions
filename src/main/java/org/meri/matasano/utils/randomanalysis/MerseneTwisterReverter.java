package org.meri.matasano.utils.randomanalysis;

import java.util.Arrays;

import org.meri.matasano.utils.encryption.MerseneTwisterRandom;

public class MerseneTwisterReverter {

  public int[] recoverMT(int[] sample) {
    int[] result = new int[sample.length];
    for (int i = 0; i < result.length; i++) {
      result[i] = recoverMTCell(sample[i]);
    }

    return result;
  }

  private int recoverMTCell(int randomNumber) {
    int result = revertFourthTwisterStep(randomNumber);
    result = revertThirdTwisterStep(result);
    result = revertSecondTwisterStep(result);
    result = revertFirstTwisterStep(result);
    return result;
  }

  public int recoverSeed(int firstMTCell, int expectedMostSignificantBit) {
    int beforeFinalMask = firstMTCell ^ MerseneTwisterRandom.GENERATING_FACTOR;
    int y = beforeFinalMask << 1;
    if ((y & 0x80000000) != expectedMostSignificantBit) 
      throw new IllegalStateException();

    return 0;
  }

  private int revertFirstTwisterStep(int number) {
    int result = number; // bits 32-21 are already OK
    result = number ^ (result >>> 11); // bits 32-10 will be OK
    result = number ^ (result >>> 11); // bits 32-0 will be OK
    return result;
  }

  private int revertSecondTwisterStep(int number) {
    int result = number; // bits 6-0 are already OK
    result = number ^ ((result << 7) & MerseneTwisterRandom.FINAL_FACTOR_1); // bits 14-0 will be OK
    result = number ^ ((result << 7) & MerseneTwisterRandom.FINAL_FACTOR_1); //bits 24-0  will be OK
    result = number ^ ((result << 7) & MerseneTwisterRandom.FINAL_FACTOR_1); //bits 30-0  will be OK
    result = number ^ ((result << 7) & MerseneTwisterRandom.FINAL_FACTOR_1); //bits 32-0  will be OK
    return result;
  }

  private int revertThirdTwisterStep(int number) {
    int result = number;
    result ^= (result << 15) & MerseneTwisterRandom.FINAL_FACTOR_2;
    return result;
  }

  private int revertFourthTwisterStep(int number) {
    int result = number;
    result ^= (result >>> 18);
    return result;
  }

  
  @SuppressWarnings("unused")
  private int[] recoverPreviousMT(int[] followingMT) { 
    int length = followingMT.length;
    int[] previousMT = Arrays.copyOf(followingMT, length);
    
    for (int idx = length - 2; idx >= 0; idx--) { 
      int lastBitOfY = recoverLastBitOfY(previousMT, idx);
      int beforeLastStep = recoverLastMtStep(previousMT, idx, lastBitOfY);
      
      int shiftedY = recoverShiftedY(previousMT, idx, beforeLastStep);
      int y = (shiftedY << 1) + lastBitOfY;
      // Not as easy as I originally through + no one actually asked for this
      // Maybe it is not even possible. 

      //int previousCellY = calculateY(previousMT, idx-1);
      
//      int last7Bits = previousCellY & MerseneTwisterRandom.BITS_0_30;
//      int firstBit = y & MerseneTwisterRandom.BIT_31;
//      int originalValue= firstBit + last7Bits;
//      System.out.println(Integer.toBinaryString(originalValue));
//      System.out.println(Integer.toBinaryString(realResult[idx]));
//      System.out.println("tralla");
      //fixNextCellBits(previousMT, idx, last7BitsOfNextCell);
      
      //fixCurrentCellBit(previousMT, idx, firstBitOfCurrentCell);
    }
    
    return previousMT;
  }

  private int recoverShiftedY(int[] previousMT, int idx, int beforeLastStep) {
    int shiftedYRemains = beforeLastStep ^ previousMT[(idx+397) % previousMT.length];
    return shiftedYRemains;
  }

  private int recoverLastBitOfY(int[] previousMT, int idx) {
    return isOdd(nextCell(previousMT, idx))? 1 : 0;
  }

  private int recoverLastMtStep(int[] previousMT, int idx, int lastBitOfY) {
    int beforeLastStep;
    if (lastBitOfY==1) {
      beforeLastStep = previousMT[idx] ^ MerseneTwisterRandom.GENERATING_FACTOR;
    } else {
      beforeLastStep = previousMT[idx];
    }
    return beforeLastStep;
  }

  private boolean isOdd(int nextCell) {
    return (nextCell << 31) !=0;
  }

  private int nextCell(int[] raw, int idx) {
    int nextIdx = (idx+1) % raw.length;
    return raw[nextIdx];
  }

}
