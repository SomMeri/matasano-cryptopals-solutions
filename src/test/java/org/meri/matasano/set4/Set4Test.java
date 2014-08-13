package org.meri.matasano.set4;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.crypto.hash.Sha1Hash;
import org.junit.Test;
import org.meri.matasano.Set4;
import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.RandomUtils;
import org.meri.matasano.utils.cryptoanalysis.Forgery;
import org.meri.matasano.utils.encryption.AESCTR;
import org.meri.matasano.utils.encryption.AESECB;
import org.meri.matasano.utils.encryption.MD4Authenticator;
import org.meri.matasano.utils.encryption.OptimizedSHA1;
import org.meri.matasano.utils.encryption.SHA1;
import org.meri.matasano.utils.encryption.SHA1Authenticator;
import org.meri.matasano.utils.oracle.CipherEditingAESCTROracle;
import org.meri.matasano.utils.oracle.ConstantKeyAESCTR;
import org.meri.matasano.utils.oracle.ConstantKeyAuthenticator;
import org.meri.matasano.utils.oracle.NoIvMessageValidatingConstantKeyAESCBC;
import org.meri.matasano.utils.webtools.Ex31Browser;
import org.meri.matasano.utils.webtools.Ex32Browser;
import org.meri.matasano.utils.webtools.ForumManager;
import org.meri.matasano.utils.webtools.JettyWebServer;

public class Set4Test {

  public static final String EX_25_OLD_CIPHER = Set4Ex25Data.GIST;
  public static final String EX_25_OLD_KEY = Set4Ex25Data.KEY;

  private static final String EX_29_SUFFIX = ";admin=true";
  private static final String EX_29_MESSAGE = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

  private static final String EX_30_SUFFIX = ";admin=true";
  private static final String EX_30_MESSAGE = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

  private static final String EX_31_FILENAME = "foo";
  private static final String EX_32_FILENAME = "foo";

  private Set4 set = new Set4();
  private ArrayManips arrayManips = new ArrayManips();
  private RandomUtils randomUtils = new RandomUtils();

  @Test
  public void ex25() {
    byte[] key = randomUtils.getExactBytes(16);

    byte[] plaintext = (new AESECB()).decrypt(Base64.decode(EX_25_OLD_CIPHER), CodecSupport.toBytes(EX_25_OLD_KEY));
    byte[] ciphertext = (new AESCTR()).encrypt(plaintext, key);

    CipherEditingAESCTROracle oracle = new CipherEditingAESCTROracle(key);
    byte[] recovered = set.recoverAESCTR(ciphertext, oracle);
    assertArrayEquals(plaintext, recovered);
  }

  @Test
  public void ex26() {
    ForumManager forum = new ForumManager(new ConstantKeyAESCTR());
    byte[] encryptedProfileCiphertext = set.createEncryptedAdminProfileFor(forum);
    assertTrue(forum.isAdminData(encryptedProfileCiphertext));
  }

  @Test
  public void ex27() {
    byte[] key = randomUtils.getExactBytes(16);

    NoIvMessageValidatingConstantKeyAESCBC cipher = new NoIvMessageValidatingConstantKeyAESCBC(key);
    byte[] recoveredKey = set.recoverKey(cipher);

    assertArrayEquals(key, recoveredKey);
  }

  @Test
  public void ex28() {
    //turns out that randomly found sha1 implementation can have a bugs
    testProblematicBytes(new byte[] { 111 });
    testProblematicInt(32768);
    testProblematicInt(111);

    //full test
    byte[] key = arrayManips.createInitializedArray(16, 1);
    byte[] message = arrayManips.createInitializedArray(22, 0);

    SHA1Authenticator authenticator = new SHA1Authenticator();
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

  private void testProblematicInt(int inputInt) {
    byte[] secondInput = arrayManips.bitewiseToBytes(new int[] { inputInt });
    testProblematicBytes(secondInput);
  }

  private void testProblematicBytes(byte[] secondInput) {
    byte[] sha132768 = SHA1.encode(secondInput);
    Sha1Hash shiro32768 = new Sha1Hash(secondInput);

    OptimizedSHA1 hash = new OptimizedSHA1();
    hash.update(secondInput);

    byte[] optimized32768 = new byte[hash.getDigestLength()];
    hash.digest(optimized32768);

    assertArrayEquals("Sha1 is wrong", shiro32768.getBytes(), optimized32768);
    assertArrayEquals("Sha1 is wrong", shiro32768.getBytes(), sha132768);
  }

  @Test
  public void ex29() {
    byte[] key = randomUtils.getInBetweenBytes(1, 50);
    ConstantKeyAuthenticator authenticator = new ConstantKeyAuthenticator(new SHA1Authenticator(), key);
    
    byte[] message = EX_29_MESSAGE.getBytes();
    byte[] authentication = authenticator.generateAuthentication(message);
    byte[] fakeSuffix = EX_29_SUFFIX.getBytes();
    
    Forgery forgedMessage = set.forgeSha1HashWithSuffix(authenticator, message, authentication, fakeSuffix);
    assertTrue(authenticator.validate(forgedMessage.getMessage(), forgedMessage.getAuthentication()));
  }

  @Test
  public void ex30() {
    byte[] key = randomUtils.getInBetweenBytes(1, 50);
    ConstantKeyAuthenticator authenticator = new ConstantKeyAuthenticator(new MD4Authenticator(), key);
    
    byte[] message = EX_30_MESSAGE.getBytes();
    byte[] authentication = authenticator.generateAuthentication(message);
    byte[] fakeSuffix = EX_30_SUFFIX.getBytes();
    
    Forgery forgedMessage = set.forgeMd4HashWithSuffix(authenticator, message, authentication, fakeSuffix);
    assertTrue(authenticator.validate(forgedMessage.getMessage(), forgedMessage.getAuthentication()));
  }

  //@Test //- DISABLED BECUASE IT WAS VERY SLOW
  public void ex31() throws InterruptedException {
    JettyWebServer server = new JettyWebServer();
    server.start();
    Thread.sleep(10);
    String signature = set.discoverValidMacFor_IncrediblySlow_Sha1HMAC(EX_31_FILENAME);
    assertTrue((new Ex31Browser()).isValidMac(EX_31_FILENAME, signature));
    server.stop();
  }

  //@Test //- DISABLED BECUASE IT WAS VERY SLOW
  public void ex32() throws InterruptedException {
    //[-111, 1, -19, -121, -110, 104, -83, 107, 32, -34, -15, -116, 12, -45, -102, -82, 65, 106, -39, 9]
    JettyWebServer server = new JettyWebServer();
    server.start();
    Thread.sleep(10);
    String signature = set.discoverValidMacFor_Faster_Sha1HMAC(EX_32_FILENAME);
    assertTrue((new Ex32Browser()).isValidMac(EX_32_FILENAME, signature));
    server.stop();
  }

}
