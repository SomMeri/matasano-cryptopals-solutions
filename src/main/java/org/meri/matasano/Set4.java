package org.meri.matasano;

import java.util.Arrays;

import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.codec.Hex;
import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.Xor;
import org.meri.matasano.utils.cryptoanalysis.Forgery;
import org.meri.matasano.utils.cryptoanalysis.MD4Forgerer;
import org.meri.matasano.utils.cryptoanalysis.SHA1Forgerer;
import org.meri.matasano.utils.oracle.CipherEditingAESCTROracle;
import org.meri.matasano.utils.oracle.ConstantKeyAuthenticator;
import org.meri.matasano.utils.oracle.NoIvMessageValidatingConstantKeyAESCBC;
import org.meri.matasano.utils.oracle.NoIvMessageValidatingConstantKeyAESCBC.InvalidPlaintextException;
import org.meri.matasano.utils.webtools.Ex31Browser;
import org.meri.matasano.utils.webtools.Ex32Browser;
import org.meri.matasano.utils.webtools.ForumManager;

public class Set4 {

  private static final int EX_32_SAMPLES = 200;
  private Xor xor = new Xor();
  private ArrayManips arrayManips = new ArrayManips();

  /**
   * Exercise 25 
   */
  public byte[] recoverAESCTR(byte[] ciphertext, CipherEditingAESCTROracle oracle) {
    byte[] faketext = new byte[ciphertext.length];
    Arrays.fill(faketext, (byte) ' ');

    byte[] editedCiphertext = oracle.edit(ciphertext, 0, faketext);
    byte[] key = xor.xor(faketext, editedCiphertext);

    return xor.xor(ciphertext, key);
  }

  /**
   * Exercise 26 
   */
  public byte[] createEncryptedAdminProfileFor(ForumManager forum) {
    String faketext1 = "            ";
    byte[] fakebytes1 = CodecSupport.toBytes(faketext1);
    String faketext2 = "------------";
    byte[] ciphertext1 = forum.createEcodedUserData(faketext1);
    byte[] ciphertext2 = forum.createEcodedUserData(faketext2);

    int offset = arrayManips.findFirstDifferingByte(ciphertext1, ciphertext2);
    byte[] modifiedCiphertextPart = Arrays.copyOfRange(ciphertext1, offset, faketext1.length() + offset);
    byte[] relevantKeyPart = xor.xor(fakebytes1, modifiedCiphertextPart);

    byte[] attackingCiphertextSegment = xor.xor(CodecSupport.toBytes("a;admin=true"), relevantKeyPart);
    System.arraycopy(attackingCiphertextSegment, 0, ciphertext1, offset, attackingCiphertextSegment.length);
    return ciphertext1;
  }

  /**
   * Exercise 27 
   */
  public byte[] recoverKey(NoIvMessageValidatingConstantKeyAESCBC cipher) {
    int blockLength = cipher.getBlockLength();
    byte[] twoBlocksOfPlaintext = arrayManips.createInitializedArray(blockLength * 2, ' ');

    byte[] ciphertext = cipher.encrypt(twoBlocksOfPlaintext);
    byte[] cipherKeyBlock = arrayManips.extractBlock(ciphertext, blockLength, 0);
    byte[] paddingBlock = arrayManips.extractLastBlock(ciphertext, blockLength);

    byte[] eliminator = arrayManips.createInitializedArray(blockLength, ' ');
    byte[] attack = arrayManips.join(eliminator, cipherKeyBlock, paddingBlock);

    try {
      cipher.decrypt(attack);
    } catch (InvalidPlaintextException ex) {
      byte[] invalidPlaintext = ex.getInvalidPlaintext();
      return arrayManips.extractBlock(invalidPlaintext, blockLength, 1);
    }

    throw new IllegalStateException("Unreachable code reached.");
  }

  /**
   * Exercise 29
   */
  public Forgery forgeSha1HashWithSuffix(ConstantKeyAuthenticator authenticator, byte[] originalMessage, byte[] originalMessageAuthentication, byte[] fakeSuffix) {
    SHA1Forgerer forgerer = new SHA1Forgerer();
    return forgerer.addSuffix(authenticator, originalMessage, originalMessageAuthentication, fakeSuffix);
  }

  /**
   * Exercise 30
   */
  public Forgery forgeMd4HashWithSuffix(ConstantKeyAuthenticator authenticator, byte[] originalMessage, byte[] originalMessageAuthentication, byte[] fakeSuffix) {
    MD4Forgerer forgerer = new MD4Forgerer();
    return forgerer.addSuffix(authenticator, originalMessage, originalMessageAuthentication, fakeSuffix);
  }

  /**
   * Exercise 31
   */
  public String discoverValidMacFor_IncrediblySlow_Sha1HMAC(String filename) {
    Ex31Browser browser = new Ex31Browser();
    System.out.println("This method is so slow, that we have to sysout how it goes - cause it looks hanged otherwise.");
    int maxLength = 20;
    byte[] signature = new byte[maxLength];
    //wake the server
    browser.measureValidationLength(filename, Hex.encodeToString(signature));
    //start attack
    long previous = browser.measureValidationLength(filename, Hex.encodeToString(signature));
    for (int indx = 0; indx < signature.length; indx++) {
      System.out.println(indx + " " + Arrays.toString(signature));
      boolean shouldMove = false;
      for (int value = Byte.MIN_VALUE; !shouldMove && (value <= Byte.MAX_VALUE); value++) {
        signature[indx] = (byte) value;
        long took = browser.measureValidationLength(filename, Hex.encodeToString(signature));
        if (Math.abs(previous - took) > 45) {
          shouldMove = true;
          if (took < previous) {
            signature[indx] = 0;
          }

          previous = Math.max(previous, took);
        }
      }
    }
    return Hex.encodeToString(signature);
  }

  /**
   * Exercise 32
   */
  public String discoverValidMacFor_Faster_Sha1HMAC(String filename) {
    Ex32Browser browser = new Ex32Browser();
    System.out.println("This method is so slow, that we have to sysout how it goes - cause it looks hanged otherwise.");
    int maxLength = 20;
    byte[] signature = new byte[maxLength];
    //wake the server
    averageTime(browser, filename, signature);
    //start attack
    for (int indx = 0; indx < signature.length; indx++) {
      System.out.println(indx + " " + Arrays.toString(signature));
      long maxTook = -1;
      int maxValue = -1;
      for (int value = Byte.MIN_VALUE; value <= Byte.MAX_VALUE; value++) {
        signature[indx] = (byte) value;
        long took = averageTime(browser, filename, signature);
        if (maxTook < took) {
          maxTook = took;
          maxValue = value;
        }
      }
      signature[indx] = (byte) maxValue;
    }
    return Hex.encodeToString(signature);
  }

  private long averageTime(Ex32Browser browser, String filename, byte[] signature) {
    long total = 0;
    long samples = EX_32_SAMPLES;
    for (int i = 0; i < samples; i++) {
      total += browser.measureValidationLength(filename, Hex.encodeToString(signature));
    }
    return total / samples;
  }
}
