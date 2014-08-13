package org.meri.matasano.set6;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.Hex;
import org.junit.Test;
import org.meri.matasano.Set6;
import org.meri.matasano.utils.cryptoanalysis.Bleichenbacher98_limited;
import org.meri.matasano.utils.cryptoanalysis.IBleichenbacher98;
import org.meri.matasano.utils.encryption.DSA;
import org.meri.matasano.utils.encryption.DSA.DSAPublicKey;
import org.meri.matasano.utils.encryption.DSA.DSASignature;
import org.meri.matasano.utils.encryption.PKCS15Padding;
import org.meri.matasano.utils.encryption.RSA;
import org.meri.matasano.utils.encryption.RSASignatureBleichenbacher;
import org.meri.matasano.utils.encryption.SHA1;
import org.meri.matasano.utils.oracle.LastBitRSAOracle;
import org.meri.matasano.utils.oracle.OneAttemptRSADecryptor;
import org.meri.matasano.utils.oracle.PaddingRSAOracle;

public class Set6Test {

  // converted with "0A".to_i(16) at    http://rubymonk.com/learning/books/1-ruby-primer/chapters/6-objects/lessons/35-introduction-to-objects
  private static final BigInteger EX_DSA_P = new BigInteger("89884656743115795391714060562757515397425322659982333453951503557945186260897603074467021329267150667179270601498386514202185870349356296751727808353958732563710461587745543679948630665057517430779539542454135056582551841462788758130134369220761262066732236795930452718468922387238066961216943830683854773169");
  private static final BigInteger EX_DSA_Q = new BigInteger("1398446195032410252040217410173702390108694920283");
  private static final BigInteger EX_DSA_G = new BigInteger("62741477437088172631393589185350035491867729832629398027831312004924312513744633269784278916027520183601208756530710011458232054971579879048852582591127008356159595963890332524237209902067360056459538632225446131921069339325466545201845714001580950381286256953162223728420823439838953735559776779136624763537");
  private static final BigInteger EX_43_Y = new BigInteger("5823053990615406155319313388236239233367841968410658366982741796746940081095581436445661710656535086682797027773423463140048889996295437507604864584563734824393676655880432230741255583991131926685648746453805615791063517148976624580495321880027165707707432467194294023501443666373988476726410973311724546583");
  private static final String EX_43_MESSAGE = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n";
  @SuppressWarnings("unused")
  private static final String EX_43_SHA1 = "d2d0714f014a9784047eaeccf956520045c45265";
  private static final String EX_43_SHA1_DECIMAL = "1203536487446634476431084512413493461057142018661";
  private static final DSASignature EX_43_SIGNATURE = new DSASignature(new BigInteger("548099063082341131477253921760299949438196259240"), new BigInteger("857042759984254168557880549501802188789837994940"));
  private static final String EX_43_EXPECTED = "0954edd5e0afe5542a4adf012611a91912a3ec16";

  private static final String EX_44_MESSAGE_1 = "Listen for me, you better listen for me now. ";
  private static final String EX_44_MESSAGE_1_HASH = "a4db3de27e2db3e5ef085ced2bced91b82e0df19";

  private static final String EX_44_MESSAGE_2 = "Pure black people mon is all I mon know. ";
  private static final String EX_44_MESSAGE_2_HASH = "d22804c4899b522b23eda34d2137cd8cc22b9ce8";

  private static final String EX_44_S2 = "1021643638653719618255840562522049391608552714967";
  private static final String EX_44_S1 = "1267396447369736888040262262183731677867615804316";
  private static final String EX_44_COMMON_R = "1105520928110492191417703162650245113664610474875";

  //this is the trick ;)
  private static final BigInteger EX_44_Y = new BigInteger("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", 16);
  private static final String EX_44_EXPECTED = "ca8f6f7c66fa362d40760d135b763eb8527d3d52";

  private static final String EX_46_INPUT = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==";

  private Set6 set = new Set6();

  @Test
  public void ex41() {
    OneAttemptRSADecryptor decriptor = new OneAttemptRSADecryptor();
    String message = "secret";
    byte[] ciphertext = decriptor.encrypt(message.getBytes());
    decriptor.decrypt(ciphertext);
    byte[] recoveredMessage = set.recoverMessage(decriptor, ciphertext);
    assertArrayEquals(message.getBytes(), recoveredMessage);
  }

  @Test
  public void ex42_RSASignatureBleichenbacher() {
    RSASignatureBleichenbacher bleichenbacher = new RSASignatureBleichenbacher();
    byte[] signedMessage = "hi dad".getBytes();
    byte[] forgedMessage = "hi mom".getBytes();
    byte[] signature = bleichenbacher.createSignature(signedMessage);
    assertTrue(bleichenbacher.isValidSignature(signedMessage, signature));
    assertFalse(bleichenbacher.isValidSignature(forgedMessage, signature));
  }

  @Test
  public void ex42() {
    RSASignatureBleichenbacher bleichenbacher = new RSASignatureBleichenbacher();
    byte[] forgedMessage = "hi mom".getBytes();

    byte[] forgedSignature = set.forgeRSASignature(forgedMessage, bleichenbacher.getPublicKey());
    assertTrue(bleichenbacher.isValidSignature(forgedMessage, forgedSignature));
  }

  @Test
  public void ex43_DSASignature() {
    DSA dsa = new DSA(EX_DSA_P, EX_DSA_Q, EX_DSA_G);
    byte[] signedMessage = "hi dad".getBytes();
    byte[] forgedMessage = "hi mom".getBytes();
    DSASignature signature = dsa.createSignature(signedMessage);
    assertTrue(dsa.isValidSignature(signedMessage, signature));
    assertFalse(dsa.isValidSignature(forgedMessage, signature));
  }

  @Test
  public void ex43_hashCompatibility() {
    DSA dsa = new DSA(EX_DSA_P, EX_DSA_Q, EX_DSA_G);
    byte[] message = EX_43_MESSAGE.getBytes();
    BigInteger hash = dsa.hash(message);
    assertEquals(new BigInteger(EX_43_SHA1_DECIMAL), hash);
  }

  @Test
  public void ex43() {
    DSAPublicKey publicKey = new DSAPublicKey(EX_DSA_P, EX_DSA_Q, EX_DSA_G, EX_43_Y);
    byte[] message = EX_43_MESSAGE.getBytes();

    BigInteger privateKey = set.getDsaPrivateKey(message, EX_43_SIGNATURE, publicKey);
    String hexadecimalHash = Hex.encodeToString(SHA1.encode(privateKey.toString(16).getBytes()));
    assertEquals(EX_43_EXPECTED, hexadecimalHash);
  }

  @Test
  public void ex44_validateHashes() {
    DSA dsa = new DSA(EX_DSA_P, EX_DSA_Q, EX_DSA_G);

    byte[] message1 = EX_44_MESSAGE_1.getBytes();
    BigInteger m1 = dsa.hash(message1);
    assertEquals(m1.toString(16), EX_44_MESSAGE_1_HASH);

    byte[] message2 = EX_44_MESSAGE_2.getBytes();
    BigInteger m2 = dsa.hash(message2);
    assertEquals(m2.toString(16), EX_44_MESSAGE_2_HASH);
  }

  @Test
  public void ex44() {
    DSAPublicKey publicKey = new DSAPublicKey(EX_DSA_P, EX_DSA_Q, EX_DSA_G, EX_44_Y);

    byte[] message1 = EX_44_MESSAGE_1.getBytes();
    byte[] message2 = EX_44_MESSAGE_2.getBytes();

    DSASignature signature1 = new DSASignature(new BigInteger(EX_44_COMMON_R), new BigInteger(EX_44_S1));
    DSASignature signature2 = new DSASignature(new BigInteger(EX_44_COMMON_R), new BigInteger(EX_44_S2));

    BigInteger privateKey = set.getDsaPrivateKey(message1, signature1, message2, signature2, publicKey);
    String hexadecimalHash = Hex.encodeToString(SHA1.encode(privateKey.toString(16).getBytes()));
    assertEquals(EX_44_EXPECTED, hexadecimalHash);
  }

  /**
   * I would point out that wiki algorithm does not allow it and would cycle
   */
  @Test
  public void ex45_noticeSomethingBad_g0() {
    DSA dsa = new DSA(EX_DSA_P, EX_DSA_Q, BigInteger.ZERO);

    byte[] message1 = "some message".getBytes();
    DSASignature signature1 = dsa.createSignature_allow0(message1);
    assertEquals(BigInteger.ZERO, signature1.getR());

    byte[] message2 = "other message".getBytes();
    DSASignature signature2 = dsa.createSignature_allow0(message2);
    assertEquals(BigInteger.ZERO, signature2.getR());
  }

  @Test
  public void ex45() {
    DSA dsa = new DSA(EX_DSA_P, EX_DSA_Q, EX_DSA_P.add(BigInteger.ONE));
    DSAPublicKey publicKey = dsa.getPublicKey();
    BigInteger y = publicKey.getY();

    BigInteger z = BigInteger.valueOf(2);
    BigInteger r = y.modPow(z, publicKey.getP()).mod(publicKey.getQ());
    BigInteger s = r.multiply(z.modInverse(publicKey.getQ())).modInverse(publicKey.getQ());
    DSASignature magic = new DSASignature(r, s);

    assertTrue(dsa.isValidSignature("Hello, world".getBytes(), magic));
    assertTrue(dsa.isValidSignature("Goodbye, world".getBytes(), magic));
  }

  @Test
  public void ex46() {
    byte[] plaintext = Base64.decode(EX_46_INPUT);
    RSA rsa = new RSA();

    byte[] ciphertext = rsa.encrypt(plaintext);
    byte[] decrypted = set.decryptRsa(ciphertext, new LastBitRSAOracle(rsa), false);
    assertArrayEquals(plaintext, decrypted);
  }

  @Test
  public void ex47() {
    boolean again = true;
    while (again) {
      again = false;
      try {
        testBleichenblacher(set.createLimitedBleichenbacher());
      } catch (IllegalStateException ex) {
        // limited bleichenbacher can not handle multiple intervals
        if (Bleichenbacher98_limited.TOO_MANY_INTERVALS.equals(ex.getMessage())) {
          System.out.println("Second attempt needed.");
          again = true;
        } else {
          throw ex;
        }
      }
    }
  }

  @Test
  public void ex48() {
    boolean again = true;
    while (again) {
      IBleichenbacher98 bleichenbacher = set.createBleichenbacher();
      testBleichenblacher(bleichenbacher);
      if (bleichenbacher.hadMultiple())
        again = false;
      else 
        System.out.println("Did not used multi-interval feature, trying again.");
    }
  }

  private void testBleichenblacher(IBleichenbacher98 bleichenbacher98) {
    byte[] message = "kick it, CC".getBytes();
    PKCS15Padding padding = new PKCS15Padding();
    RSA rsa = new RSA(128);
    byte[] paddedMessage = padding.padPkcs15(message, rsa.getPublicKey());
    byte[] ciphertext = rsa.encrypt(paddedMessage);

    PaddingRSAOracle oracle = new PaddingRSAOracle(rsa);
    byte[] plaintext = bleichenbacher98.decryptRSAPaddingOracle(ciphertext, oracle);

    System.out.println("        n: " + Arrays.toString(rsa.getPublicKey().getN().toByteArray()));
    System.out.println(" original: " + Arrays.toString(paddedMessage));
    System.out.println("decrypted: " + Arrays.toString(plaintext));
    assertArrayEquals(paddedMessage, plaintext);
  }

  @Test
  public void test() {
    byte n[] = {95, 109, -81, -35, 101, -33, -35, 108, -8, -127, 93, 8, -68, -37, -96, -60, -88, -21, 25, 72, -115, 83, -73, 39, 121, 34, 4, -18, 45, 104, -3, 115};
    byte plain[] = {0, 2, -33, -24, 120, -77, -25, 57, 43, -87, -69, 56, 101, 53, 110, 101, -42, 29, -112, -123, 0, 107, 105, 99, 107, 32, 105, 116, 44, 32, 67, 67};
    System.out.println(n.length + " " + plain.length);
  }
}
