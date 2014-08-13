package org.meri.matasano.utils.oracle;

import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.encryption.AESECB;
import org.meri.matasano.utils.encryption.CoreCipher;

public class ConstantKeyConstantSuffixAESECB implements EncryptingOracleCipher, CoreCipher {

  private final byte[] key;
  private final byte[] suffix;
  private final boolean shouldAddRandomPrefix;

  private AESECB aesecb = new AESECB();
  private ArrayManips arrayManips = new ArrayManips();

  public ConstantKeyConstantSuffixAESECB(byte[] suffix) {
    this(suffix, false);
  }

  public ConstantKeyConstantSuffixAESECB(byte[] suffix, boolean shouldAddRandomPrefix) {
    RandomNumberGenerator generator = new SecureRandomNumberGenerator();
    key = generator.nextBytes(aesecb.getBlockSize()).getBytes();
    this.suffix = suffix;
    this.shouldAddRandomPrefix = shouldAddRandomPrefix;
  }

  public byte[] decrypt(byte[] ciphertext) {
    return aesecb.decrypt(ciphertext, key);
  }

  public byte[] encrypt(byte[] plaintext) {
    if (shouldAddRandomPrefix) {
      arrayManips.join(generateRandomArray(), plaintext);
    }
    return aesecb.encrypt(arrayManips.join(plaintext, suffix), key);
  }

  public int getBlockSize() {
    return aesecb.getBlockSize();
  }

  public int getBlockLength() {
    return aesecb.getBlockSize();
  }

  private byte[] generateRandomArray() {
    RandomNumberGenerator generator = new SecureRandomNumberGenerator();
 // shorter messages make tests faster
    int randomLength = (Math.abs(generator.nextBytes(1).getBytes()[0]) % 127) + 1; 
    return generator.nextBytes(randomLength).getBytes();
  }

}
