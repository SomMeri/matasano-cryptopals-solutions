package org.meri.matasano.utils.webtools;

import java.net.URL;
import java.net.URLConnection;

import org.apache.commons.io.IOUtils;

public class Wget {

  public String wget(String urlStr) {
    try {
      URL url = new URL(urlStr);
      URLConnection con = url.openConnection();
      String str = IOUtils.toString(con.getInputStream(), "ISO-8859-1");
      return str;
    } catch (Throwable th) {
      throw new RuntimeException(th);
    }
  }
}
