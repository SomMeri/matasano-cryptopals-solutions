package org.meri.matasano.utils.webtools;

import java.util.HashMap;
import java.util.Map;

public class ProfileManager {
  
  private CookiesHelper cookiesHelper = new CookiesHelper();
  
  public String createProfileCookieString(String email) {
    Map<String, String> result = new HashMap<String, String>();
    result.put("email", sanitize(email));
    result.put("role", "user");
    result.put("uid", "10");
    
    return cookiesHelper.generateCookies(result);
  }

  private String sanitize(String email) {
    return email.replaceAll("&", "").replaceAll("=", "");
  }
  
}
