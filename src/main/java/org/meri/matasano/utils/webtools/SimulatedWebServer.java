package org.meri.matasano.utils.webtools;

import org.apache.shiro.codec.CodecSupport;
import org.meri.matasano.utils.encryption.CoreCipher;
import org.meri.matasano.utils.oracle.ConstantKeyConstantSuffixAESECB;

public class SimulatedWebServer {
  
  private ProfileManager profileManager = new ProfileManager();
  private CookiesHelper cookiesHelper = new CookiesHelper();
  private CoreCipher cipher;
  
  public SimulatedWebServer() {
    cipher = new ConstantKeyConstantSuffixAESECB(new byte[0]);
  }
  
  public byte[] createEcodedProfileFor(String email) {
    String cookie = profileManager.createProfileCookieString(email);
    return cipher.encrypt(CodecSupport.toBytes(cookie));
  }
  
  public String getRole(byte[] encryptedProfileCookies) {
    byte[] decrypt = cipher.decrypt(encryptedProfileCookies);
    String cookiesString = CodecSupport.toString(decrypt);
    return cookiesHelper.parseCookies(cookiesString).get(CookiesHelper.ROLE);
  }
}
