package org.meri.matasano.set1;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;
import org.meri.matasano.Set1;

public class Set1Test {

  public static final String EX_1_HEXADECIMAL = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
  public static final String EX_1_BASE64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

  public static final String EX_2_FIRST = "1c0111001f010100061a024b53535009181c";
  public static final String EX_2_SECOND = "686974207468652062756c6c277320657965";
  public static final String EX_2_EXPECTED = "746865206b696420646f6e277420706c6179";

  public static final String EX_3_CIPHER = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

  public static final List<String> EX_4_CIPHERS = Set1Ex4Data.GIST;

  public static final String EX_5_EXPECTED = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
  public static final String EX_5_INPUT = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
  public static final String EX_5_KEY = "ICE";

  public static final String EX_6_CIPHER = Set1Ex6Data.GIST;

  public static final String EX_7_CIPHER = Set1Ex7Data.GIST;
  public static final String EX_7_KEY = Set1Ex7Data.KEY;

  public static final List<String> EX_8_CIPHERS = Set1Ex8Data.GIST;

  @Test
  public void ex1_HexToBase64() {
    Set1 set1 = new Set1();
    assertEquals(EX_1_BASE64, set1.hexToBase64(EX_1_HEXADECIMAL));
  }

  @Test
  public void ex1_Base64ToHex() {
    Set1 set1 = new Set1();
    assertEquals(EX_1_HEXADECIMAL, set1.base64ToHex(EX_1_BASE64));
  }

  @Test
  public void ex2() {
    Set1 set1 = new Set1();
    assertEquals(EX_2_EXPECTED, set1.xorHex(EX_2_FIRST, EX_2_SECOND));
  }

  @Test
  public void ex3() {
    Set1 set1 = new Set1();
    assertEquals(Set1Answers.EXERCISE_3, set1.decodeOneCharacterXor(EX_3_CIPHER));
  }

  @Test
  public void ex4() {
    Set1 set1 = new Set1();
    assertEquals(Set1Answers.EXERCISE_4, set1.detectOneCharacterXor(EX_4_CIPHERS));
  }

  @Test
  public void ex5() {
    Set1 set1 = new Set1();
    assertEquals(EX_5_EXPECTED, set1.xorThem(EX_5_INPUT, EX_5_KEY));
  }

  @Test
  public void ex6() {
    Set1 set1 = new Set1();
    assertEquals(Set1Answers.EXERCISE_6, set1.breakMultipleTimePad(EX_6_CIPHER));
  }

  @Test
  public void ex7() {
    Set1 set1 = new Set1();
    assertEquals(Set1Answers.EXERCISE_7, set1.decryptAES128ECB(EX_7_CIPHER, EX_7_KEY));
  }

  @Test
  public void ex8() {
    Set1 set1 = new Set1();
    assertEquals(Set1Answers.EXERCISE_8, set1.detectEcb(EX_8_CIPHERS, 16));
  }

}
