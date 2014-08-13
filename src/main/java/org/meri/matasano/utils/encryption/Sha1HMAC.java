package org.meri.matasano.utils.encryption;


public class Sha1HMAC extends HMAC {
  
  @Override
  protected byte[] hash(byte[] data) {
    return SHA1.encode(data);
  }

  @Override
  protected int getBlocksize() {
    return 64;
  }
  
}
