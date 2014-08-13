package org.meri.matasano.utils.cryptoanalysis;

public class Forgery {

  private final byte[] message;
  private final byte[] authentication;

  public Forgery(byte[] message, byte[] authentication) {
    super();
    this.message = message;
    this.authentication = authentication;
  }

  public byte[] getMessage() {
    return message;
  }

  public byte[] getAuthentication() {
    return authentication;
  }


}
