package org.meri.matasano.utils.webtools;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

public class CookiesHelper {
  
  public static final String EMAIL = "email";
  public static final String UID = "uid";
  public static final String ROLE = "role";

  public String generateCookies(Map<String, String> input) {
    StringBuilder builder = new StringBuilder();
    
    // the exercise is much easier if cookie string is in exactly the same order
    // as mail example had
    // I'm not sure how much cheating this is
    if (input.containsKey(EMAIL)) {
      builder.append(EMAIL).append("=").append(input.remove(EMAIL));
      if (!input.isEmpty())
        builder.append("&");
    }

    if (input.containsKey(UID)) {
      builder.append(UID).append("=").append(input.remove(UID));
      if (!input.isEmpty())
        builder.append("&");
    }

    if (input.containsKey(ROLE)) {
      builder.append(ROLE).append("=").append(input.remove(ROLE));
      if (!input.isEmpty())
        builder.append("&");
    }

    // the rest of the code
    Iterator<Entry<String, String>> entrySet = input.entrySet().iterator();
    while (entrySet.hasNext()) {
      Entry<String, String> entry = entrySet.next();
      builder.append(entry.getKey()).append("=").append(entry.getValue());
      if (entrySet.hasNext())
        builder.append("&");
    }
    return builder.toString();
  }

  public Map<String, String> parseCookies(String cookiesString) {
    String[] cookies = cookiesString.split("&");

    Map<String, String> result = new HashMap<String, String>();
    for (String cake : cookies) {
      addCookie(result, cake);
    }

    return result;
  }

  private void addCookie(Map<String, String> result, String cake) {
    String[] split = cake.split("=");
    result.put(split[0], split[1]);
  }
}
