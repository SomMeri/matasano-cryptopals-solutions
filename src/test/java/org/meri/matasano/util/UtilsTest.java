package org.meri.matasano.util;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;

import org.apache.shiro.codec.CodecSupport;
import org.junit.Test;
import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.Bits;
import org.meri.matasano.utils.cryptoanalysis.Hamming;
import org.meri.matasano.utils.encryption.AESCBC;
import org.meri.matasano.utils.encryption.AESCTR;
import org.meri.matasano.utils.encryption.IncrementalNonce;
import org.meri.matasano.utils.encryption.MerseneTwisterRandom;
import org.meri.matasano.utils.encryption.OptimizedSHA1;
import org.meri.matasano.utils.encryption.PadValidatingAESCBC;
import org.meri.matasano.utils.encryption.XorCBC;
import org.meri.matasano.utils.oracle.ConstantKeyAESCBC;
import org.meri.matasano.utils.oracle.IVInCiphertextConstantKeyAESCBC;
import org.meri.matasano.utils.randomanalysis.BitwiseMerseneTwisterAnlyzer;
import org.meri.matasano.utils.webtools.CookiesHelper;

public class UtilsTest {

  private final Bits bits = new Bits();

  private ArrayManips arrayUtils = new ArrayManips();
  private Hamming hamming = new Hamming();

  @Test
  public void transpose() {
    byte[] input = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    int key = 3;
    byte[] transposed = arrayUtils.transpose(input, key);
    assertArrayEquals(input, Arrays.copyOf(arrayUtils.transpose(transposed, arrayUtils.transposedBlockLength(input, key)), input.length));
  }

  @Test
  public void hamming() {
    assertEquals(37, hamming.distance("this is a test", "wokka wokka!!!"));
  }

  @Test
  public void testXorCbcShort() {
    byte[] plaintext = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
    byte[] iv = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
    byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
    XorCBC cipher = new XorCBC();
    assertArrayEquals(plaintext, cipher.decrypt(cipher.encrypt(plaintext, key, iv), key, iv));
  }

  @Test
  public void testXorCbcLong() {
    byte[] plaintext = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10, 11, 12, 13, 14, 15, 16 };
    byte[] iv = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
    byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
    XorCBC cipher = new XorCBC();
    assertArrayEquals(plaintext, cipher.decrypt(cipher.encrypt(plaintext, key, iv), key, iv));
  }

  @Test
  public void testAesCbcShort() {
    byte[] plaintext = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
    byte[] iv = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
    byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
    AESCBC cipher = new AESCBC();
    assertArrayEquals(plaintext, cipher.decrypt(cipher.encrypt(plaintext, key, iv), key, iv));
  }

  @Test
  public void testAesCbcLong() {
    byte[] plaintext = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10, 11, 12, 13, 14, 15, 16 };
    byte[] iv = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
    byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
    AESCBC cipher = new AESCBC();
    assertArrayEquals(plaintext, cipher.decrypt(cipher.encrypt(plaintext, key, iv), key, iv));
  }

  @Test
  public void cookieParser() {
    CookiesHelper cookieParser = new CookiesHelper();
    Map<String, String> cookies = cookieParser.parseCookies("foo=bar&baz=qux&zap=zazzle");
    assertEquals(3, cookies.size());
    assertEquals("bar", cookies.get("foo"));
    assertEquals("qux", cookies.get("baz"));
    assertEquals("zazzle", cookies.get("zap"));

    String generatedCookies = cookieParser.generateCookies(cookies);
    Map<String, String> parsedCookies = cookieParser.parseCookies(generatedCookies);
    assertEquals(3, parsedCookies.size());
    assertEquals("bar", parsedCookies.get("foo"));
    assertEquals("qux", parsedCookies.get("baz"));
    assertEquals("zazzle", parsedCookies.get("zap"));
  }

  @Test
  public void testConstantKeyAESCBC() {
    ConstantKeyAESCBC cipher = new ConstantKeyAESCBC();
    String source = "plaintext";
    byte[] input = CodecSupport.toBytes(source);

    byte[] output = cipher.encrypt(input);
    byte[] decryptedOutput = cipher.decrypt(output);

    assertEquals(source, CodecSupport.toString(decryptedOutput));
  }

  @Test
  public void testPaddingValidatinfIVInCiphertextConstantKeyAESCBC() {
    IVInCiphertextConstantKeyAESCBC cipher = new IVInCiphertextConstantKeyAESCBC(new PadValidatingAESCBC());
    String source = "plaintext";
    byte[] input = CodecSupport.toBytes(source);

    byte[] output = cipher.encrypt(input);
    byte[] decryptedOutput = cipher.decrypt(output);

    assertEquals(source, CodecSupport.toString(decryptedOutput));
  }

  @Test
  public void testIncrementalNonce_start() {
    IncrementalNonce zeroNonce = new IncrementalNonce(8, 8);
    assertArrayEquals(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, zeroNonce.getBytes());
    zeroNonce.increment();
    assertArrayEquals(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 }, zeroNonce.getBytes());
    zeroNonce.increment();
    assertArrayEquals(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0 }, zeroNonce.getBytes());
  }

  @Test
  public void testIncrementalNonce_long() {
    IncrementalNonce longNonce = new IncrementalNonce(8, new byte[] { Byte.MAX_VALUE, Byte.MAX_VALUE, Byte.MAX_VALUE, 0, 0, 0, 0, 0 });
    assertArrayEquals(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, Byte.MAX_VALUE, Byte.MAX_VALUE, Byte.MAX_VALUE, 0, 0, 0, 0, 0 }, longNonce.getBytes());
    longNonce.increment();
    assertArrayEquals(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 }, longNonce.getBytes());
    longNonce.increment();
    assertArrayEquals(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0 }, longNonce.getBytes());
  }

  @Test
  public void testAESCTREncryption() {
    AESCTR cipher = new AESCTR();

    byte[] plaintext = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10, 11, 12, 13, 14, 15, 16 };
    byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
    assertArrayEquals(plaintext, cipher.decrypt(cipher.encrypt(plaintext, key), key));
  }

  @Test
  public void testBitwiseMerseneTwisterAnalyzer() {
    SecureRandom random = new SecureRandom();

    for (int bitUnderTest = 0; bitUnderTest < 16; bitUnderTest++) {
      BitwiseMerseneTwisterAnlyzer testee = new BitwiseMerseneTwisterAnlyzer(bitUnderTest);
      for (int attemptNum = 0; attemptNum < 32000; attemptNum++) {
        int number = random.nextInt();

        int randomInt = mTGeneration(number);
        int expectedBit = bits.lastBit(randomInt >>> bitUnderTest);
        int randomBit = testee.getRandomBit(number);

        assertEquals("Bit " + bitUnderTest + " for number " + number + " was wrong.", expectedBit, randomBit);
      }
    }
  }

  private int mTGeneration(int fullNumber) {
    int[] MT = Arrays.copyOf(new int[] { fullNumber }, MerseneTwisterRandom.MT_LENGTH);
    MerseneTwisterRandom twister = new MerseneTwisterRandom(MT);
    int result = twister.getRandomInt();

    return result;
  }

  @Test 
  public void testOptimizedSHA1() {
    OptimizedSHA1 hash = new OptimizedSHA1();
    hash.update(new byte[] {2});
    hash.update(new byte[] {1});
    
    byte[] multipleUpdates = new byte[hash.getDigestLength()];
    hash.digest(multipleUpdates);

    hash.reset();
    hash.update(new byte[] { 2, 1 });
    byte[] oneUpdate = new byte[hash.getDigestLength()];
    hash.digest(oneUpdate);

    assertArrayEquals(multipleUpdates, oneUpdate);
  }

  @Test
  public void bitewiseToBytes() {
    byte[] bytes = new byte[] { 56, -122, 9, -62, 64, -106, 28, 118, -121, 49, -97, -60, -101, 41, -14, -39, -95, 82, 116, 49 };
    int[] ints = new int[] { 948308418, 1083579510, -2026790972, -1691749671, -1588431823 };
    assertArrayEquals(bytes, arrayUtils.bitewiseToBytes(ints));
  }

  @Test
  public void bitewiseToIntegers() {
    byte[] bytes = new byte[] { 56, -122, 9, -62, 64, -106, 28, 118, -121, 49, -97, -60, -101, 41, -14, -39, -95, 82, 116, 49 };
    int[] ints = new int[] { 948308418, 1083579510, -2026790972, -1691749671, -1588431823 };
    int[] result = arrayUtils.bitewiseToIntegers(bytes);
    assertArrayEquals(ints, result);

    ByteBuffer buffer = ByteBuffer.wrap(new byte[] {56, -122, 9, -62});
    buffer.order(ByteOrder.BIG_ENDIAN);  // if you want little-endian
    int test = buffer.getInt();
    assertEquals(948308418, test);
    assertEquals(948308418, arrayUtils.bitewiseToIntegers(new byte[] {56, -122, 9, -62})[0]);

  }
}
