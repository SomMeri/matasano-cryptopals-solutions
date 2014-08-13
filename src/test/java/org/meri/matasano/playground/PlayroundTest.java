package org.meri.matasano.playground;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.SecureRandom;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.crypto.hash.Sha1Hash;
import org.junit.Test;
import org.meri.matasano.set1.Set1Answers;
import org.meri.matasano.set1.Set1Test;
import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.Xor;
import org.meri.matasano.utils.cryptoanalysis.HammingBasedMultipleTimePadCryptanalysis;
import org.meri.matasano.utils.encryption.MerseneTwisterRandom;
import org.meri.matasano.utils.encryption.OptimizedSHA1Authentication;

public class PlayroundTest {

  private ArrayManips arrayManips = new ArrayManips();
  private Xor xor = new Xor();
  private HammingBasedMultipleTimePadCryptanalysis decoder = new HammingBasedMultipleTimePadCryptanalysis();

  @Test
  public void set1_ex6_smallCase() {
    String plaintext = Set1Test.EX_5_INPUT;
    String key = Set1Test.EX_5_KEY;
    byte[] cipher = xor.xor(CodecSupport.toBytes(plaintext), CodecSupport.toBytes(key));
    assertEquals(plaintext, CodecSupport.toString(decoder.decode(cipher, 3)).substring(0, plaintext.length()));
  }

  @Test
  public void set1_ex6_hand_guess() {
    String decoded = CodecSupport.toString(xor.xor(Base64.decode(Set1Test.EX_6_CIPHER), CodecSupport.toBytes("Terminator X: Bring the noise")));
    assertEquals(Set1Answers.EXERCISE_6, decoded);
  }
  
  @Test
  public void set2_ex22_last_step_reverses_itself() {
    SecureRandom realRandomGenerator = new SecureRandom();
    for (int i = -257; i <= 257; i++) {
      int testOn = realRandomGenerator.nextInt();
      asserEqualsReportBinary(i, revertFourthTwisterStep(fourthTwisterStep(i)));
      asserEqualsReportBinary(testOn, revertFourthTwisterStep(fourthTwisterStep(testOn)));
      asserEqualsReportBinary(i, revertThirdTwisterStep(thirdTwisterStep(i)));
      asserEqualsReportBinary(testOn, revertThirdTwisterStep(thirdTwisterStep(testOn)));
      asserEqualsReportBinary(i, revertSecondTwisterStep(secondTwisterStep(i)));
      asserEqualsReportBinary(testOn, revertSecondTwisterStep(secondTwisterStep(testOn)));
      asserEqualsReportBinary(i, revertFirstTwisterStep(firstTwisterStep(i)));
      asserEqualsReportBinary(testOn, revertFirstTwisterStep(firstTwisterStep(testOn)));
    }
  }

  private int secondTwisterStep(int number) {
    int result = number;
    result ^= (result << 7) & MerseneTwisterRandom.FINAL_FACTOR_1;
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

  private void asserEqualsReportBinary(int first, int second) {
    assertEquals(Integer.toBinaryString(first), Integer.toBinaryString(second));
  }

  public int fourthTwisterStep(int number) {
    int result = number;
    result ^= (result >>> 18);
    return result;
  }

  public int revertFourthTwisterStep(int number) {
    return fourthTwisterStep(number);
  }

  public int thirdTwisterStep(int number) {
    int result = number;
    result ^= (result << 15) & MerseneTwisterRandom.FINAL_FACTOR_2;
    return result;
  }

  public int revertThirdTwisterStep(int number) {
    return thirdTwisterStep(number);
  }

  public int firstTwisterStep(int number) {
    int result = number;
    result ^= (result >>> 11);
    return result;
  }

  public int revertFirstTwisterStep(int number) {
    int result = number; // bits 32-21 are already OK
    result = number ^ (result >>> 11); // bits 32-10 will be OK
    result = number ^ (result >>> 11); // bits 32-0 will be OK
    return result;
  }

  @Test
  public void ex28_optimized() {
    byte[] key = arrayManips.createInitializedArray(16, 1);
    byte[] message = arrayManips.createInitializedArray(22, 0);

    //SHA1Authentication authenticator = new SHA1Authentication();
    OptimizedSHA1Authentication authenticator = new OptimizedSHA1Authentication();
    byte[] authentication = authenticator.generateAuthentication(message, key);
    assertTrue(authenticator.validate(message, authentication, key));

    message[0] = 1;
    assertFalse(authenticator.validate(message, authentication, key));
    message[0] = 0;
    assertTrue(authenticator.validate(message, authentication, key));

    key[0] = 0;
    assertFalse(authenticator.validate(message, authentication, key));
    key[0] = 1;
    assertTrue(authenticator.validate(message, authentication, key));

    byte original = authentication[0];
    authentication[0] = 1;
    assertFalse(authenticator.validate(message, authentication, key));
    authentication[0] = original;

    byte[] prefixedData = arrayManips.join(key, message);

    Sha1Hash shiro = new Sha1Hash(prefixedData);
    assertArrayEquals(shiro.getBytes(), authentication);
  }
}
