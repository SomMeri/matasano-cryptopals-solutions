package org.meri.matasano.set3;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.junit.Test;
import org.meri.matasano.Set3;
import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.RandomUtils;
import org.meri.matasano.utils.encryption.AESCTR;
import org.meri.matasano.utils.encryption.MerseneTwisterRandom;
import org.meri.matasano.utils.encryption.MersenneTwisterCTR;
import org.meri.matasano.utils.encryption.ShortKeyMersenneTwisterCTR;
import org.meri.matasano.utils.webtools.PasswordResetTokenManager;
import org.meri.matasano.utils.webtools.SessionManager;

public class Set3Test {

  private static final List<String> EX_17_INPUTS = Arrays.asList("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=", "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=", "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==", "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==", "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl", "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==", "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==", "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=", "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=", "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93");

  public static final String EX_18_KEY = "YELLOW SUBMARINE";
  public static final String EX_18_CIPHERTEXT = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

  private Set3 set = new Set3();
  private ArrayManips arrayManips = new ArrayManips();
  private RandomUtils randomUtils = new RandomUtils();

  @Test
  public void ex17() {
    // simulate random selection
    Collections.shuffle(EX_17_INPUTS);

    // we will try them all, just to make sure code really works 
    for (String cookie : EX_17_INPUTS) {
      //initiate session manager with new key and iv
      SessionManager sessionManager = new SessionManager();
      // test the routine
      byte[] cookieCiphertext = sessionManager.encrypt(cookie);
      String cookiePlaintext = set.decryptLeakingPkcsN7Padding(cookieCiphertext, sessionManager);
      assertEquals(cookie, cookiePlaintext);
    }
  }

  @Test
  public void ex18() {
    assertEquals(Set3Answers.EXERCISE_18, set.aesCtrDecrypt(EX_18_CIPHERTEXT, EX_18_KEY));
  }

  @Test
  public void ex18_other_things_encryption() {
    AESCTR cipher = new AESCTR();

    byte[] plaintext = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10, 11, 12, 13, 14, 15, 16 };
    byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
    assertArrayEquals(plaintext, cipher.decrypt(cipher.encrypt(plaintext, key), key));
  }

  @Test
  public void ex19() {
    List<String> plaintexts = Set3Ex19Data.GIST;
    List<byte[]> ciphers = aesctrEncryptAll(plaintexts);
    //crack them
    List<byte[]> allCracked = set.ineffectivelyCrackThemAll(ciphers);

    //validate results
    assertAllfullyMatch(plaintexts, allCracked);
  }

  private void assertAllfullyMatch(List<String> base64Plaintexts, List<byte[]> allCracked) {
    for (int i = 0; i < allCracked.size(); i++) {
      byte[] original = Base64.decode(base64Plaintexts.get(i));
      byte[] cracked = allCracked.get(i);
      assertArrayEquals("Text " + i, original, cracked);
    }
  }

  @Test
  public void ex20() {
    List<String> plaintexts = Set3Ex20Data.GIST;
    List<byte[]> ciphers = aesctrEncryptAll(plaintexts);
    //crack them
    List<byte[]> allCracked = set.crackThemAll(ciphers);

    //validate results
    assertAllPartiallyMatch(plaintexts, allCracked);
  }

  private void assertAllPartiallyMatch(List<String> base64Plaintexts, List<byte[]> allCracked) {
    for (int i = 0; i < allCracked.size(); i++) {
      byte[] original = Base64.decode(base64Plaintexts.get(i));
      byte[] cracked = allCracked.get(i);
      assertArrayEquals(Arrays.copyOf(original, cracked.length), cracked);
    }
  }

  private List<byte[]> aesctrEncryptAll(List<String> plaintexts) {
    byte[] key = new byte[] { '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6' };
    AESCTR aesctr = new AESCTR();
    List<byte[]> ciphers = new ArrayList<byte[]>();
    for (String base64 : plaintexts) {
      byte[] plaintext = Base64.decode(base64);
      byte[] ciphertext = aesctr.encrypt(plaintext, key);

      ciphers.add(ciphertext);
    }
    return ciphers;
  }

  @Test
  public void ex21() {
    // I did not found competiting Mersene Twister implementation. Those I found
    // probably implements different variants then wiki specified.
    //
    // Expected outputs are whatever came up from my implementation first time I run it. 
    MerseneTwisterRandom merseneTwister = new MerseneTwisterRandom(15);
    assertArrayEquals(new int[] { -649323064, -800665867, 768352140, -1755116923, 233488247 }, merseneTwister.getInts(5));
    assertArrayEquals(new int[] { 476682624 }, merseneTwister.getInts(1));
    assertArrayEquals(new int[] { 1552795804, -779056485 }, merseneTwister.getInts(2));
    assertArrayEquals(new int[] { 1182837959, -315066677, -2018633643, 107172470, 1313911727, -763223843, 1307707409, -1202912531, 479925151, 911000599 }, merseneTwister.getInts(10));
  }

  @Test
  public void ex22() {
    int seed = Math.abs((int) (new Date()).getTime());
    // These tests are already too slow for my taste, so I'm going to go with 
    // simulation. Pretending to wait.
    int randomWaitingPeriod = getRandomMiliseconds();
    int timestamp = seed + randomWaitingPeriod;

    int guessedSeed = set.discoverTimestampUsedAsSeed(new MerseneTwisterRandom(seed), timestamp);
    assertEquals(seed, guessedSeed);
  }

  private int getRandomMiliseconds() {
    SecureRandom realRandomGenerator = new SecureRandom();
    int randomWaitingPeriod = (int) TimeUnit.SECONDS.toMillis(Math.abs(realRandomGenerator.nextInt()) % 960 + 40);
    randomWaitingPeriod += Math.abs(realRandomGenerator.nextInt()) % 1000;
    return randomWaitingPeriod;
  }

  @Test
  public void ex23() {
    SecureRandom realRandomGenerator = new SecureRandom();
    int seed = realRandomGenerator.nextInt();

    MerseneTwisterRandom merseneTwister = new MerseneTwisterRandom(seed);
    MerseneTwisterRandom clone = set.cloneTwister(merseneTwister);

    assertArrayEquals(merseneTwister.getInts(100), clone.getInts(100));
  }

  @Test
  public void ex24_encryption() {
    byte[] plaintext = CodecSupport.toBytes("AAAAAAAAAAAAAA");
    int key = 987;

    MersenneTwisterCTR cipher = new MersenneTwisterCTR();
    byte[] ciphertext = cipher.encrypt(plaintext, key);
    byte[] decoded = cipher.decrypt(ciphertext, key);

    assertArrayEquals(plaintext, decoded);
  }

  @Test
  public void ex24_keyRecovery() {
    byte[] plaintext = arrayManips.join(randomUtils.getBytes(), CodecSupport.toBytes("AAAAAAAAAAAAAA"));
    int key = randomUtils.getRandom16BitKey();
    ShortKeyMersenneTwisterCTR cipher = new ShortKeyMersenneTwisterCTR();
    byte[] ciphertext = cipher.encrypt(plaintext, key);

    int recoveredKey = set.recoverShortMersenneTwisterCTRKey(ciphertext);
    assertEquals(key, recoveredKey);
  }

  @Test
  public void ex24_passwordResetToken() {
    PasswordResetTokenManager manager = new PasswordResetTokenManager();
    //generate and test token
    byte[] token = manager.generatePasswordResetToken();
    assertTrue(manager.isPasswordResetToken(token));
    //it is very unlikely that we would generate valid token by random
    assertFalse(manager.isPasswordResetToken(randomUtils.getBytes()));
  }

}
