package org.meri.matasano;

import java.util.ArrayList;
import java.util.List;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.Ascii;
import org.meri.matasano.utils.Xor;
import org.meri.matasano.utils.cryptoanalysis.HammingBasedMultipleTimePadCryptanalysis;
import org.meri.matasano.utils.cryptoanalysis.LeakingPkcsN7PaddingInCBCAnalyzer;
import org.meri.matasano.utils.cryptoanalysis.SpacesPositionsBasedMultipleTimePadCryptanalysis;
import org.meri.matasano.utils.encryption.AESCTR;
import org.meri.matasano.utils.encryption.MerseneTwisterRandom;
import org.meri.matasano.utils.encryption.ShortKeyMersenneTwisterCTR;
import org.meri.matasano.utils.oracle.PaddingValidatingOracle;
import org.meri.matasano.utils.randomanalysis.MerseneTwisterReverter;
import org.meri.matasano.utils.webtools.SessionManager;

public class Set3 {

  private ArrayManips arrayUtils = new ArrayManips();
  private Xor xor = new Xor();
  private Ascii ascii = new Ascii();

  /** Exercise 17 */
  public String decryptLeakingPkcsN7Padding(byte[] cookieCiphertext, final SessionManager sessionManager) {
    LeakingPkcsN7PaddingInCBCAnalyzer analyzer = new LeakingPkcsN7PaddingInCBCAnalyzer(new PaddingValidatingOracle() {

      public boolean validatePadding(byte[] ciphertext) {
        return sessionManager.validateSessionCookieEncryption(ciphertext);
      }

      public int getBlockLength() {
        return sessionManager.getBlockLength();
      }
    });
    byte[] result = analyzer.decryptLeakingPkcsN7Padding(cookieCiphertext);
    return CodecSupport.toString(result);
  }

  /** Exercise 18 
   * 
   * The answer is "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ".
   * 
   * */
  public String aesCtrDecrypt(String base64Ciphertext, String key) {
    AESCTR aesctr = new AESCTR();
    return CodecSupport.toString(aesctr.decrypt(Base64.decode(base64Ciphertext), CodecSupport.toBytes(key)));
  }

  /** Exercise 19  
   * 
   * Observations:
   * 1.) If we xor two ciphetexts, result is equal to xor of plaintexts.
   * 2.) Space xor letter is always a letter.
   * 
   * So, if we xor ciphertext with all others and get a lot of letters 
   * at some character position, then that position probably contains 
   * space.
   * 
   * This recovered most of the key, because spaces are frequent and we 
   * have lot of samples available. Remaining few have been easy to guess.
   *
   * */
  public List<byte[]> ineffectivelyCrackThemAll(List<byte[]> ciphers) {
    SpacesPositionsBasedMultipleTimePadCryptanalysis analyzer = new SpacesPositionsBasedMultipleTimePadCryptanalysis();
    byte[] key = analyzer.recoverMostOfTheKey(ciphers);
    
    //Some parts of the key have not been recovered. Mostly those
    //in the end, because only few ciphertexts are long enough. Plus
    //the first one, no text starts with space.
    byte[] longCipher = ciphers.get(4);
    key[0] = (byte)(longCipher[0] ^ 'I');
    key[30] = (byte)(longCipher[30] ^ 'e');
    key[33] = (byte)(longCipher[33] ^ 'e');
    key[34] = (byte)(longCipher[34] ^ 'a');
    key[35] = (byte)(longCipher[35] ^ 'd');
    
    byte[] longerCipher = ciphers.get(37);
    key[36] = (byte)(longerCipher[36] ^ 'n');
    key[37] = (byte)(longerCipher[37] ^ ',');
    
    List<byte[]> result = new ArrayList<byte[]>();
    for (byte[] ciphertext : ciphers) {
      result.add(xor.xorDontWrap(key, ciphertext));
    }
    
    return result;
  }

  /** Exercise 20  */
  public List<byte[]> crackThemAll(List<byte[]> ciphers) {
    int minimumLenth = arrayUtils.findShortest(ciphers);
    List<byte[]> shortTexts = arrayUtils.copyOfAll(ciphers, minimumLenth);
    byte[] textToCrack = arrayUtils.joinBlocks(shortTexts, minimumLenth);

    HammingBasedMultipleTimePadCryptanalysis analyzer = new HammingBasedMultipleTimePadCryptanalysis();
    byte[] plaintext = analyzer.decode(textToCrack, minimumLenth);
    List<byte[]> resultAsBytes = arrayUtils.splitBlocksList(plaintext, minimumLenth);
    return resultAsBytes;
  }

  /** Exercise 21 - it is in @see MerseneTwisterRandom class.  */

  /** Exercise 22 */
  public int discoverTimestampUsedAsSeed(MerseneTwisterRandom merseneTwister, int currentTimestamp) {
    int expectedInt = merseneTwister.getRandomInt();
    for (int guess = currentTimestamp; guess > 0; guess--) {
      MerseneTwisterRandom twister = new MerseneTwisterRandom(guess);
      if (twister.getRandomInt() == expectedInt)
        return guess;
    }
    return 0;
  }

  /**
   * Exercise 23
   * 
   * Answers to questions:
   * 1.) I would apply some one way function to generated integers before returning them.
   * 2.) Cryptographic hash is such one way function, it would make this cloning method 
   *     hard (impossible in practice).  
   */
  public MerseneTwisterRandom cloneTwister(MerseneTwisterRandom merseneTwister) {
    int[] sample = merseneTwister.getInts(MerseneTwisterRandom.MT_LENGTH);
    MerseneTwisterReverter reverter = new MerseneTwisterReverter();
    int[] MT = reverter.recoverMT(sample);

    MerseneTwisterRandom clone = new MerseneTwisterRandom(MT);
    //move clone state
    clone.getInts(sample.length);
    return clone;
  }

  /** Exercise 24 
   * 
   * Last part of the exercise, password reset token is implemented in PasswordResetTokenManager 
   * class. At least, I think that I did what I was supposed to. If it is not the case, let me 
   * know.
   * */
  public int recoverShortMersenneTwisterCTRKey(byte[] ciphertext) {
    ShortKeyMersenneTwisterCTR cipher = new ShortKeyMersenneTwisterCTR();
    int maximum = -1;
    int result = 0;
    
    for (int guess=0; guess< ShortKeyMersenneTwisterCTR.RELEVANT_KEY_BITS; guess++) {
      byte[] plaintext = cipher.decrypt(ciphertext, guess);
      int score = 0;
      byte letter = plaintext[plaintext.length - score - 1];
      while (score < plaintext.length && ascii.isEnglishCharacter(letter)) {
        score++;
        letter = plaintext[plaintext.length - score - 1];
      }
      if (maximum < score) {
        maximum = score;
        result = guess;
      }
    }
    
    return result;
  }

}
