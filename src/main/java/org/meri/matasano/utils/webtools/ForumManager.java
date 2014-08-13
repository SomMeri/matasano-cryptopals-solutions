package org.meri.matasano.utils.webtools;

import java.util.HashMap;
import java.util.Map;

import org.apache.shiro.codec.CodecSupport;
import org.meri.matasano.utils.encryption.CoreCipher;

public class ForumManager {

  private static final String ADMIN = "admin";
  private static final String PREPEND = "comment1=cooking%20MCs;userdata=";
  private static final String APPEND = ";comment2=%20like%20a%20pound%20of%20bacon";
  
  private CoreCipher cipher;

  public ForumManager(CoreCipher cipher) {
    this.cipher = cipher;
  }

  public byte[] createEcodedUserData(String userdata) {
    String fulldata = PREPEND + sanitize(userdata) + APPEND;
    byte[] result = cipher.encrypt(CodecSupport.toBytes(fulldata));
    
    return result;
  }
  
  public boolean isAdminData(byte[] ciphertext) {
    byte[] decrypt = cipher.decrypt(ciphertext);
    String dataString = CodecSupport.toString(decrypt);
    
    Map<String, String> inputData = parseInputData(dataString);
    if (!inputData.containsKey(ADMIN))
      return false;

    return "true".equals(inputData.get(ADMIN));
  }
  
  private String sanitize(String input) {
    return input.replaceAll(";", "&#59;").replaceAll("=", "&#61");
  }
  
  private Map<String, String> parseInputData(String input) {
    String[] variables = input.split(";");

    Map<String, String> result = new HashMap<String, String>();
    for (String variable : variables) {
      addValue(result, variable);
    }

    return result;
  }

  private void addValue(Map<String, String> result, String variable) {
    String[] split = variable.split("=");
    result.put(split[0], split[1]);
  }
  
}
