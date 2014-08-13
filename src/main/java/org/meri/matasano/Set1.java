package org.meri.matasano;

import java.util.List;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.codec.Hex;
import org.meri.matasano.utils.Xor;
import org.meri.matasano.utils.cryptoanalysis.ECBAnalyzer;
import org.meri.matasano.utils.cryptoanalysis.HammingBasedMultipleTimePadCryptanalysis;
import org.meri.matasano.utils.cryptoanalysis.HammingBasedMultipleTimePadCryptanalysis.DecodedResult;
import org.meri.matasano.utils.encryption.AESECB;

public class Set1 {
  
  private Xor xor = new Xor();
  private HammingBasedMultipleTimePadCryptanalysis decoder = new HammingBasedMultipleTimePadCryptanalysis();

  /**
   * Exercise 1: I used apache shiro {@link http://shiro.apache.org/} to encode
   * and decode stuff.
   */
  public String hexToBase64(String hex) {
    byte[] raw = Hex.decode(hex);
    return Base64.encodeToString(raw);
  }

  public String base64ToHex(String base64) {
    byte[] raw = Base64.decode(base64);
    return Hex.encodeToString(raw);
  }

  /** Exercise 2 */
  public String xorHex(String first, String second) {
    return xor.xorHex(first, second);
  }

  /** Exercise 3 */
  public String decodeOneCharacterXor(String hex) {
    DecodedResult result = decoder.decodeAssumeOneLetterLongKey(Hex.decode(hex));
    return CodecSupport.toString(result.assumeClearResult());
  }

  /** Exercise 4 */
  public String detectOneCharacterXor(List<String> ex4Ciphers) {
    int maxScore = -1;
    DecodedResult result = null;

    for (String cipher : ex4Ciphers) {
      DecodedResult decoded = decoder.decodeAssumeOneLetterLongKey(Hex.decode(cipher));

      if (maxScore < decoded.getAsciiCharactersCount()) {
        maxScore = decoded.getAsciiCharactersCount();
        result = decoded;
      }
    }

    return CodecSupport.toString(result.assumeClearResult());
  }

  /** Exercise 5 */
  public String xorThem(String cipher, String key) {
    return Hex.encodeToString(xor.xor(CodecSupport.toBytes(cipher), CodecSupport.toBytes(key)));
  }

  /** Exercise 6 */
  public String breakMultipleTimePad(String cipher) {
    byte[] rawCipher = Base64.decode(cipher);
    return CodecSupport.toString(decoder.decode(rawCipher));
  }

  /** Exercise 7 */
  public String decryptAES128ECB(String base64Ciphertext, String key) {
    AESECB aesecb = new AESECB();
    byte[] plaintext = aesecb.decrypt(Base64.decode(base64Ciphertext), CodecSupport.toBytes(key));

    return CodecSupport.toString(plaintext);
  }

  /** Exercise 8 */
  public String detectEcb(List<String> hexCiphers, int blockLength) {
    ECBAnalyzer detector = new ECBAnalyzer();
    return detector.detectEcb(hexCiphers, blockLength);
  }


}
