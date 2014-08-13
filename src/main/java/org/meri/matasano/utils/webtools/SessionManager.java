package org.meri.matasano.utils.webtools;

import org.apache.shiro.codec.CodecSupport;
import org.meri.matasano.utils.encryption.PadValidatingAESCBC;
import org.meri.matasano.utils.encryption.PkcsN7Padding.InvalidPaddingException;
import org.meri.matasano.utils.oracle.IVInCiphertextConstantKeyAESCBC;

public class SessionManager {
  
  private IVInCiphertextConstantKeyAESCBC cipher = new IVInCiphertextConstantKeyAESCBC(new PadValidatingAESCBC());
  
  public byte[] encrypt(String cookie) {
    return cipher.encrypt(CodecSupport.toBytes(cookie));
  }
  
  public boolean validateSessionCookieEncryption(byte[] encryptedCookie) {
    try {
      cipher.decrypt(encryptedCookie);
      return true;
    } catch (InvalidPaddingException ex) {
      return false;
    }
  }
  
  public int getBlockLength() {
    return cipher.getBlockLength();
  }

}
