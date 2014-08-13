package org.meri.matasano.utils.randomanalysis;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.lang.ArrayUtils;
import org.meri.matasano.utils.Bits;
import org.meri.matasano.utils.encryption.MerseneTwisterRandom;

/**
 * Note to self: if you are too sleep deprived to think and decide to code anyway,
 * you will end up with perfectly functional, debugged and uterly useless class.
 * 
 * Such as this one.
 *
 */
public class BitwiseMerseneTwisterAnlyzer {
  
  private final Bits bits = new Bits();

  private int targetBit;
  private int[] bitDependencies;
  private Set<Integer> compositionsWithResultOne;

  public BitwiseMerseneTwisterAnlyzer(int targetBit) {
    this.targetBit = targetBit;
    initialize();
  }

  private void initialize() {
    bitDependencies = createBitDependenciesArray();
    compositionsWithResultOne = Collections.unmodifiableSet(generateCompositionsWithResultOne());
  }

  private Set<Integer> generateCompositionsWithResultOne() {
    Set<Integer> givesOne = new HashSet<Integer>();

    for (int composition = 0; composition < powerOf2(bitDependencies.length); composition++) {
      int spreadedComposition = spreadCompositionBits(composition);
      int derivedRandom = mTGeneration(spreadedComposition);
      int resultBit = bits.lastBit(derivedRandom >>> targetBit);
      if (resultBit == 1) {
        givesOne.add(composition);
      }

    }
    return givesOne;
  }

  private int spreadCompositionBits(int composition) {
    int spreadedComposition = 0;
    int copy = composition;
    for (int j = 0; j < bitDependencies.length; j++) {
      int bitValue = bits.lastBit(copy);
      spreadedComposition += bitValue * powerOf2(bitDependencies[j]);
      copy = copy >>> 1;
    }
    return spreadedComposition;
  }

  private int powerOf2(int exponent) {
    return 1 << exponent;
  }

  private int extractComposition(int input) {
    int composition = 0;
    for (int j = 0; j < bitDependencies.length; j++) {
      int shiftedInput = input >>> bitDependencies[j];
      int bit = bits.lastBit(shiftedInput);
      composition += bit * powerOf2(j);
    }
    return composition;
  }

  private int[] createBitDependenciesArray() {
    int[] firstLamma = new int[1];
    firstLamma[0] = targetBit;
    int[] secondLamma = nextDependencyArray(firstLamma, 18, true);
    int[] thirdLamma = nextDependencyArray(secondLamma, 15, false);
    int[] fourthLamma = nextDependencyArray(thirdLamma, 7, false);
    int[] fifthLamma = nextDependencyArray(fourthLamma, 11, true);

    HashSet<Integer> set = new HashSet<Integer>(Arrays.asList(ArrayUtils.toObject(fifthLamma)));
    int[] bitDependencies = ArrayUtils.toPrimitive(set.toArray(new Integer[0]));
    Arrays.sort(bitDependencies);
    return bitDependencies;
  }

  private int[] nextDependencyArray(int[] previous, int shift, boolean mtStepShiftsRight) {
    int[] result = Arrays.copyOf(previous, previous.length * 2);
    int index = 0;
    for (int i = 0; i < previous.length; i++) {
      result[index++] = previous[i];

      int shiftedIndex;
      if (mtStepShiftsRight) {
        shiftedIndex = previous[i] + shift;
      } else {
        shiftedIndex = previous[i] - shift;
      }
      if (shiftedIndex >= 0 & shiftedIndex < 32)
        result[index++] = shiftedIndex;
    }
    return Arrays.copyOf(result, index);
  }

  private int mTGeneration(int fullNumber) {
    int[] MT = Arrays.copyOf(new int[] { fullNumber }, MerseneTwisterRandom.MT_LENGTH);
    MerseneTwisterRandom twister = new MerseneTwisterRandom(MT);
    int result = twister.getRandomInt();

    return result;
  }

  public int getRandomBit(int mtCellContent) {
    int composition = extractComposition(mtCellContent);
    int resultBit = compositionsWithResultOne.contains(composition) ? 1 : 0;
    return resultBit;
  }

  public int[] getBitDependencies() {
    return bitDependencies;
  }

  public Set<Integer> getCompositionsWithResultOne() {
    return compositionsWithResultOne;
  }
}
