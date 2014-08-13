package org.meri.matasano.utils.encryption;

public interface Authenticator {

  public abstract byte[] generateAuthentication(byte[] message, byte[] key);

  public abstract boolean validate(byte[] message, byte[] authentication, byte[] key);

}