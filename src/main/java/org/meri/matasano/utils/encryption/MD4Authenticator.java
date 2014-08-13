package org.meri.matasano.utils.encryption;

import java.util.Arrays;

import org.meri.matasano.utils.ArrayManips;

public class MD4Authenticator implements Authenticator {
  
  private ArrayManips arrayManips = new ArrayManips();
  
  /* (non-Javadoc)
   * @see org.meri.matasano.utils.encryption.Authenticator#generateAuthentication(byte[], byte[])
   */
  public byte[] generateAuthentication(byte[] message, byte[] key) {
    byte[] content = arrayManips.join(key, message);
    MD4 md4 = new MD4();
    md4.update(content, 0);
    return md4.digest();
  }
  
  /* (non-Javadoc)
   * @see org.meri.matasano.utils.encryption.Authenticator#validate(byte[], byte[], byte[])
   */
  public boolean validate(byte[] message, byte[] authentication, byte[] key) {
    byte[] expected = generateAuthentication(message, key);
    return Arrays.equals(expected, authentication);
  }

}
