package org.meri.matasano.utils.encryption;

import java.util.Arrays;

public class OptimizedSHA1Authentication {
  
  private OptimizedSHA1 hash = new OptimizedSHA1();
  
  public byte[] generateAuthentication(byte[] message, byte[] key) {
    hash.reset();
    hash.update(key);
    hash.update(message);

    byte[] auth = new byte[hash.getDigestLength()];
    hash.digest(auth);
    return auth;
  }
  
  public boolean validate(byte[] message, byte[] authentication, byte[] key) {
    byte[] expected = generateAuthentication(message, key);
    return Arrays.equals(expected, authentication);
  }

}
