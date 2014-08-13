package org.meri.matasano.utils.oracle;

import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.meri.matasano.utils.encryption.AESCBC;
import org.meri.matasano.utils.encryption.AESECB;

public class ECBCBCOracle implements EncryptingOracleCipher {
  
  private OracleMode lastRunningMode = OracleMode.NONE;
  
  public OracleMode getLastRunningMode() {
    return lastRunningMode;
  }

  public byte[] encrypt(byte[] plaintext) {
    byte[] paddedPlaintext = encloseInRandomPadding(plaintext);
    
    lastRunningMode = randomMode();
    if (lastRunningMode==OracleMode.ECB) {
      AESECB aesecb = new AESECB();
      return aesecb.encrypt(paddedPlaintext, randomBytes(getBlockSize()));
    } else {
      AESCBC aescbc = new AESCBC();
      return aescbc.encrypt(paddedPlaintext, randomBytes(16), randomBytes(16));
    }
  }

  public int getBlockSize() {
    return 16;
  }
  
  private byte[] encloseInRandomPadding(byte[] plaintext) {
    int prefixLength = randomByte(getMaximumPrefix() - getMinimumPrefix()) + getMinimumPrefix();
    int suffixLength = randomByte(5) + 5;
    
    byte[] result = randomBytes(prefixLength + suffixLength + plaintext.length);
    System.arraycopy(plaintext, 0, result, prefixLength, plaintext.length);
    return result;
  }

  public int getMaximumPrefix() {
    return 10;
  }

  public int getMinimumPrefix() {
    return 5;
  }

  private byte[] randomBytes(int length) {
    RandomNumberGenerator generator = new SecureRandomNumberGenerator();
    return generator.nextBytes(length).getBytes();
  }

  private byte randomByte(int max) {
    RandomNumberGenerator generator = new SecureRandomNumberGenerator();
    return (byte) (generator.nextBytes(1).getBytes()[0] % max);
  }

  private OracleMode randomMode() {
    return 0==randomByte(2) ? OracleMode.ECB : OracleMode.CBC;
  }

  public enum OracleMode {
    ECB, CBC, NONE;
  }
}
