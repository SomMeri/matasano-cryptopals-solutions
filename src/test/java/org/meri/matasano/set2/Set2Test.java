package org.meri.matasano.set2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.junit.Test;
import org.meri.matasano.Set2;
import org.meri.matasano.utils.encryption.PkcsN7Padding.InvalidPaddingException;
import org.meri.matasano.utils.oracle.ConstantKeyAESCBC;
import org.meri.matasano.utils.oracle.ConstantKeyConstantSuffixAESECB;
import org.meri.matasano.utils.oracle.ECBCBCOracle;
import org.meri.matasano.utils.oracle.ECBCBCOracle.OracleMode;
import org.meri.matasano.utils.webtools.ForumManager;
import org.meri.matasano.utils.webtools.SimulatedWebServer;

public class Set2Test {

  public static final String EX_9_INPUT = "YELLOW SUBMARINE";
  public static final int EX_9_BLOCK_LENGTH = 20;
  public static final String EX_9_OUTPUT = "YELLOW SUBMARINE\u0004\u0004\u0004\u0004";

  public static final String EX_10_CIPHERTEXT = Set2Ex10Data.GIST;
  public static final String EX_10_IV = Set2Ex10Data.IV;
  public static final String EX_10_KEY = Set2Ex10Data.KEY;
  
  private static final int EX_11_NUMBER_OF_TESTS = 20;

  private static final String EX_12_SUFFIX = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
  public static final String EX_15_A_INPUT = "ICE ICE BABY\u0004\u0004\u0004\u0004";
  public static final String EX_15_A_OUTPUT = "ICE ICE BABY";
  public static final String EX_15_B_INPUT = "ICE ICE BABY\u0005\u0005\u0005\u0005";
  public static final String EX_15_C_INPUT = "ICE ICE BABY\u0001\u0002\u0003\u0004";

  
  @Test
  public void ex9() {
    Set2 set2 = new Set2();
    assertEquals(EX_9_OUTPUT, set2.padPkcsN7(EX_9_INPUT, EX_9_BLOCK_LENGTH));
  }

  @Test
  public void ex10() {
    Set2 set2 = new Set2();
    assertEquals(Set2Answers.EXERCISE_10, set2.decryptMultipleTimePadInECB(EX_10_CIPHERTEXT, EX_10_KEY, EX_10_IV));
  }
  
  @Test
  public void ex11() {
    Set2 set2 = new Set2();
    ECBCBCOracle oracle = new ECBCBCOracle();
    for (int i = 0; i < EX_11_NUMBER_OF_TESTS; i++) {
      OracleMode guess = set2.oracleEncryptAndGuess(oracle);
      assertEquals(oracle.getLastRunningMode(), guess);
    }
  }

  @Test
  public void ex12() {
    Set2 set2 = new Set2();
    ConstantKeyConstantSuffixAESECB serverToHack = new ConstantKeyConstantSuffixAESECB(Base64.decode(EX_12_SUFFIX));
    String plaintext = set2.decryptSuffix(serverToHack);
    assertEquals(CodecSupport.toString(Base64.decode(EX_12_SUFFIX)), plaintext);
  }

  @Test
  public void ex13() {
    Set2 set2 = new Set2();
    SimulatedWebServer webServer = new SimulatedWebServer();
    byte[] encryptedProfileCookies = set2.createEncryptedAdminProfileFor(webServer);
    assertEquals("admin", webServer.getRole(encryptedProfileCookies));
  }

  @Test
  public void ex14() {
    Set2 set2 = new Set2();
    ConstantKeyConstantSuffixAESECB serverToHack = new ConstantKeyConstantSuffixAESECB(Base64.decode(EX_12_SUFFIX), true);
    String plaintext = set2.decryptSuffixBewareRandomPrefix(serverToHack);
    assertEquals(CodecSupport.toString(Base64.decode(EX_12_SUFFIX)), plaintext);
  }

  @Test
  public void ex15_a() {
    Set2 set2 = new Set2();
    assertEquals(EX_15_A_OUTPUT, set2.validateAndRemovePkcsN7(EX_15_A_INPUT));
  }

  @Test(expected=InvalidPaddingException.class)
  public void ex15_b() {
    Set2 set2 = new Set2();
    set2.validateAndRemovePkcsN7(EX_15_B_INPUT);
  }

  @Test(expected=InvalidPaddingException.class)
  public void ex15_c() {
    Set2 set2 = new Set2();
    set2.validateAndRemovePkcsN7(EX_15_C_INPUT);
  }

  @Test
  public void ex16() {
    Set2 set2 = new Set2();
    ForumManager forum = new ForumManager(new ConstantKeyAESCBC());
    byte[] encryptedProfileCiphertext = set2.createEncryptedAdminProfileFor(forum);
    assertTrue(forum.isAdminData(encryptedProfileCiphertext));
  }
}
