package org.meri.matasano.utils.encryption;

import java.util.Arrays;

import org.meri.matasano.utils.ArrayManips;

public class SHA1Authenticator implements Authenticator {
  
  private ArrayManips arrayManips = new ArrayManips();
  
  public byte[] generateAuthentication(byte[] message, byte[] key) {
    byte[] content = arrayManips.join(key, message);
    return SHA1.encode(content);
  }
  
  public boolean validate(byte[] message, byte[] authentication, byte[] key) {
    byte[] expected = generateAuthentication(message, key);
    return Arrays.equals(expected, authentication);
  }

}
