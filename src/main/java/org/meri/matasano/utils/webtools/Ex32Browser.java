package org.meri.matasano.utils.webtools;

import java.util.Date;

public class Ex32Browser {
  
  public long measureValidationLength(String filename, String signature) {
    Wget wget = new Wget();
    long startTime = (new Date()).getTime();
    wget.wget(toUrl(filename, signature));
    long endTime = (new Date()).getTime();
    long took = endTime - startTime;
    //System.out.println(page);
    return took;
  }

  public boolean isValidMac(String filename, String signature) {
    Wget wget = new Wget();
    String page = wget.wget(toUrl(filename, signature));

    System.out.println(page);

    boolean isValid = page.contains("validity: true");
    return isValid;
  }

  private String toUrl(String filename, String signature) {
    return "http://localhost:8080/Set4Ex32/?file=" + filename + "&signature=" + signature;
  }

}
