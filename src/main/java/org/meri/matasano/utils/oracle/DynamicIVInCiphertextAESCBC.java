package org.meri.matasano.utils.oracle;

import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;

public class DynamicIVInCiphertextAESCBC extends IVInCiphertextConstantKeyAESCBC {

  public DynamicIVInCiphertextAESCBC(byte[] sessionKey) {
    super(sessionKey);
  }

  @Override
  protected byte[] getIv() {
    RandomNumberGenerator generator = new SecureRandomNumberGenerator();
    return generator.nextBytes(getBlockSize()).getBytes();
  }

}
