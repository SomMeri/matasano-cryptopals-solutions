package org.meri.matasano;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.Xor;
import org.meri.matasano.utils.cryptoanalysis.ECBAnalyzer;
import org.meri.matasano.utils.cryptoanalysis.ECBAnalyzer.BlockInfo;
import org.meri.matasano.utils.encryption.AESCBC;
import org.meri.matasano.utils.encryption.PkcsN7Padding;
import org.meri.matasano.utils.oracle.ConstantKeyConstantSuffixAESECB;
import org.meri.matasano.utils.oracle.ECBCBCOracle;
import org.meri.matasano.utils.oracle.ECBCBCOracle.OracleMode;
import org.meri.matasano.utils.oracle.EncryptingOracleCipher;
import org.meri.matasano.utils.oracle.RandomPrefixRemovingOracleCipher;
import org.meri.matasano.utils.webtools.ForumManager;
import org.meri.matasano.utils.webtools.SimulatedWebServer;

public class Set2 {

  private ArrayManips arrayManips = new ArrayManips();
  private Xor xor = new Xor();

  /** Exercise 9 */
  public String padPkcsN7(String raw, int blockLength) {
    PkcsN7Padding padding = new PkcsN7Padding();
    return CodecSupport.toString(padding.padPkcsN7(CodecSupport.toBytes(raw), blockLength));
  }

  /** Exercise 10 - AES! CBC 
   * 
   * Decrypted plaintext contains the same Vanilla Ice song as exercises 6 and 7. It
   * starts with "I'm back and I'm ringin' the bell \nA rockin' on the mike ...".
   * */
  public String decryptMultipleTimePadInECB(String base64Ciphertext, String keyString, String ivString) {
    byte[] ciphertext = Base64.decode(base64Ciphertext);
    final byte[] key = CodecSupport.toBytes(keyString);
    byte[] iv = CodecSupport.toBytes(ivString);

    AESCBC aesCbc = new AESCBC();
    byte[] plaintext = aesCbc.decrypt(ciphertext, key, iv);

    return CodecSupport.toString(plaintext);
  }

  /** Exercise 11 - The detector constructs plaintext with repeating blocks
   * and let oracle encrypt it. If ciphertext contains repeating blocks, then 
   * it probably is ECB.
   * */
  public OracleMode oracleEncryptAndGuess(ECBCBCOracle oracle) {
    ECBAnalyzer detector = new ECBAnalyzer();

    if (detector.isECBEncryption(oracle, oracle.getBlockSize())) {
      return OracleMode.ECB;
    } else {
      return OracleMode.CBC;
    }
  }

  /** Exercise 12 
   * 
   * The algorithm is implemented in {@see SuffixCrackingAlgorithm} class. The ciphertext 
   * decrypts into:
   * 
   * "Rollin' in my 5.0 \nWith my rag-top down so my hair can blow \nThe girlies on standby waving just to say hi \nDid you stop? No, I just drove by \n";.
   * 
   * */
  public String decryptSuffix(ConstantKeyConstantSuffixAESECB server) {
    ECBAnalyzer detector = new ECBAnalyzer();
    return CodecSupport.toString(detector.decryptServerAddedSuffix(server));
  }

  /** Exercise 13 
   *  This solution relies on role being the last in cookies string. It would not work with 
   *  role being on any other place.
   *  
   *  - Works for: email=xxxx&uid=xxxx&role=xxx
   *  - Does not work for: role=xxx&uid=xxxx&email=xxxx
   *  
   *  If I was supposed to find another solution, let me know please.
   */
  public byte[] createEncryptedAdminProfileFor(final SimulatedWebServer webServer) {
    ECBAnalyzer analyzer = new ECBAnalyzer();
    // validate input server - unimportant code
    BlockInfo blockSizeInfo = analyzer.discoverBlockSizeInfo(new EncryptingOracleCipher() {
      
      public byte[] encrypt(byte[] plaintext) {
        return webServer.createEcodedProfileFor(CodecSupport.toString(plaintext));
      }
    });
    
    if (blockSizeInfo.getBlockLength()!=16)
      throw new IllegalStateException("This solution requires 16 bytes block size. It is not general enough to handle " + blockSizeInfo.getBlockLength());
    
    // attack
    byte[] adminBlockFullCipher = webServer.createEcodedProfileFor("fo@bar.comadmin\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000b");
    byte[] adminBlock = arrayManips.extractBlock(adminBlockFullCipher, 16, 1);

    byte[] attack = webServer.createEcodedProfileFor("foooo@bar.com");
    arrayManips.replaceLastBlock(attack, adminBlock);
    return attack;
  }
  
  /** Exercise 14 
   * WARNING - this solution is based on incorrect reading of the challenge. See issue #1 on this repository.
   * ISSUE: https://github.com/SomMeri/matasano-cryptopals-solutions/issues/1
   * 
   * "What's harder about doing this?"
   * 
   * It is harder to predict position of cipher blocks we are interested in.  
   * 
   * "How would you overcome that obstacle?"
   * 
   * I modified each encryption query by prepending it with three blocks of constant data. I call 
   * them "signature". Attacked server then add its own prefix, encrypts it and sends me result.
   * 
   * - Send data: three-constant-blocks || attack || target-bytes
   * - Encrypted data: random-prefix || three-constant-blocks || attack || target-bytes
   * 
   * If the length of servers prefix is divisible by 16, then three-constant-blocks corresponds to three 
   * repeated blocks in ciphertext. The code removes those three blocks and everything leading to them.
   * Remaining ciphertext is valid encryption of "attack || target-bytes"
   * 
   * Random prefix divisible by 16 leads to:
   * - Attacked server answer: aescbc(random-prefix) || aescbc(three-constant-blocks) || aescbc(attack || target-bytes)
   * - Modified answer: aescbc(attack || target-bytes)
   * 
   * If the length of servers prefix is NOT divisible by 16, then the ciphertex does not contain three consecutive 
   * repeated blocks. If that is the case, code asks the server to encrypt the same input again.
   * 
   * This random prefix removal logic is implemented in {@see RandomPrefixRemovingOracleCipher}.
   *
   * Cracking algorithm uses exactly the same code as in exercise 12. Only difference is that
   * target server gets hit with more requests.  
   * 
   * */
  public String decryptSuffixBewareRandomPrefix(final ConstantKeyConstantSuffixAESECB server) {
    ECBAnalyzer detector = new ECBAnalyzer();
    EncryptingOracleCipher modifiedServer = new RandomPrefixRemovingOracleCipher(server, server.getBlockSize());
    return CodecSupport.toString(detector.decryptServerAddedSuffix(modifiedServer));
  }

  /** Exercise 15 */
  public String validateAndRemovePkcsN7(String input) {
    PkcsN7Padding padding = new PkcsN7Padding();
    return CodecSupport.toString(padding.validateAndremovePadding(CodecSupport.toBytes(input)));
  }

  /** Exercise 16 
   * 
   * Encode user data equivalent to two blocks of data. Use the cipher block corresponding to first 
   * block to modify plaintext of the second. 
   * 
   * */
  public byte[] createEncryptedAdminProfileFor(final ForumManager forum) {
    ECBAnalyzer analyzer = new ECBAnalyzer();
    // validate input server - unimportant code
    BlockInfo blockSizeInfo = analyzer.discoverBlockSizeInfo(new EncryptingOracleCipher() {
      
      public byte[] encrypt(byte[] plaintext) {
        return forum.createEcodedUserData(CodecSupport.toString(plaintext));
      }
    });
    
    if (blockSizeInfo.getBlockLength()!=16)
      throw new IllegalStateException("This solution requires 16 bytes block size. It is not general enough to handle " + blockSizeInfo.getBlockLength());
    
    // attack
    byte[] initialCiphertext = forum.createEcodedUserData("1234567890123456<admin>true<aa>b");
    byte[] modifier = new byte[initialCiphertext.length];
    modifier[2*blockSizeInfo.getBlockLength()] = 7;
    modifier[2*blockSizeInfo.getBlockLength()+6] = 3;
    modifier[2*blockSizeInfo.getBlockLength()+11] = 7;
    modifier[2*blockSizeInfo.getBlockLength()+14] = 3;
    
    byte[] attack = xor.xor(initialCiphertext, modifier);
    forum.isAdminData(attack);
    return attack;
  }

}
