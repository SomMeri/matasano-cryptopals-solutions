package org.meri.matasano.utils.webtools.servlets;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.codec.Hex;
import org.meri.matasano.utils.encryption.Sha1HMAC;

@SuppressWarnings("serial")
public class Set4Ex31Servlet extends HttpServlet {

  private static final byte[] SECRET_KEY = new byte[16]; // array of zeros is as secret as anything else 
  private static final int SLEEP_TIME = 50;
  private static final String SIGNATURE = "signature";
  private static final String FILE = "file";

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    String filename = (String) request.getParameter(FILE);
    String signature = (String) request.getParameter(SIGNATURE);
    
    boolean isValid = validate(filename, signature);
    
    response.setContentType("text/html");
    response.setStatus(HttpServletResponse.SC_OK);
    
    response.getWriter().println("<h1>Hello SimpleServlet</h1>");
    response.getWriter().println("filename: "+ filename + "<br>");
    response.getWriter().println("signature: "+ signature + "<br>");
    response.getWriter().println("expected: "+ new String(Hex.encode(expectedSignature(filename))) + "<br>");
    response.getWriter().println("<br>");
    response.getWriter().println("validity: "+ isValid + "<br>");
  }

  private boolean validate(String filename, String signature) {
    byte[] expectedAuthentication = expectedSignature(filename);
    byte[] clientAuthentication = Hex.decode(signature);
    
    
    boolean isValid = insecureCompare(expectedAuthentication, clientAuthentication);
    return isValid;
  }

  private boolean insecureCompare(byte[] first, byte[] second) {
    if (first.length!=second.length)
      return false;
    
    for (int i = 0; i < second.length; i++) {
      if (first[i]!=second[i])
        return false;
      
      try {
        Thread.sleep(SLEEP_TIME);
      } catch (InterruptedException e) {
        throw new RuntimeException(e);
      }
    }
    return true;
  }

  private byte[] expectedSignature(String filename) {
    Sha1HMAC sha1hmac = new Sha1HMAC();
    byte[] expectedAuthentication = sha1hmac.generateAuthentication(CodecSupport.toBytes(filename), SECRET_KEY); 
    return expectedAuthentication;
  }
}
