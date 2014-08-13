package org.meri.matasano.utils.oracle;

import org.meri.matasano.utils.RandomUtils;
import org.meri.matasano.utils.encryption.Authenticator;

public class ConstantKeyAuthenticator {
  
  private final byte[] key;
  private final Authenticator authenticator;
  
  public ConstantKeyAuthenticator(Authenticator authenticator) {
    this(authenticator, (new RandomUtils()).getInBetweenBytes(1, 50));
  }

  public ConstantKeyAuthenticator(Authenticator authenticator, byte[] key) {
    this.authenticator = authenticator;
    this.key = key;
  }

  public byte[] generateAuthentication(byte[] message) {
    return authenticator.generateAuthentication(message, key);
  }

  public boolean validate(byte[] message, byte[] authentication) {
    return authenticator.validate(message, authentication, key);
  }

}
