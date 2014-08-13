package org.meri.matasano.utils;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RandomUtils {

  private static final int BITS_0_16 = 0xffff;

  public int getRandom16BitKey() {
    SecureRandom realRandomGenerator = new SecureRandom();
    return realRandomGenerator.nextInt() & BITS_0_16;
  }

  public byte[] getBytes() {
    return getAtLeastBytes(0);
  }

  public byte[] getAtLeastBytes(int minLength) {
    SecureRandom realRandomGenerator = new SecureRandom();
    byte[] result = new byte[minLength + Math.abs(realRandomGenerator.nextInt()) % 256];
    realRandomGenerator.nextBytes(result);

    return result;
  }

  public byte[] getInBetweenBytes(int minLength, int maxLength) {
    SecureRandom realRandomGenerator = new SecureRandom();
    byte[] result = new byte[minLength + Math.abs(realRandomGenerator.nextInt()) % (maxLength-minLength)];
    realRandomGenerator.nextBytes(result);

    return result;
  }

  public byte[] getExactBytes(int length) {
    SecureRandom realRandomGenerator = new SecureRandom();
    byte[] result = new byte[length];
    realRandomGenerator.nextBytes(result);

    return result;
  }

  public int getInt(int min, int max) {
    SecureRandom realRandomGenerator = new SecureRandom();
    int random = Math.abs(realRandomGenerator.nextInt()) % (max-min);
    return random + min;
  }

  public BigInteger getPositiveBigInteger(BigInteger max) {
    SecureRandom realRandomGenerator = new SecureRandom();
    BigInteger result = new BigInteger(max.bitLength(), realRandomGenerator);
    return result.mod(max);
  }

}
