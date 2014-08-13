package org.meri.matasano.utils.oracle;

import org.meri.matasano.utils.RandomUtils;
import org.meri.matasano.utils.encryption.Authenticator;
import org.meri.matasano.utils.encryption.MD4Authenticator;

public class ConstantKeyMD4Authentication {
  
  private final byte[] key;
  private Authenticator authenticator = new MD4Authenticator();
  
  public ConstantKeyMD4Authentication() {
    RandomUtils radom = new RandomUtils();
    key = radom.getInBetweenBytes(1, 50);
  }

  public ConstantKeyMD4Authentication(byte[] key) {
    this.key = key;
  }

  public byte[] generateAuthentication(byte[] message) {
    return authenticator.generateAuthentication(message, key);
  }

  public boolean validate(byte[] message, byte[] authentication) {
    return authenticator.validate(message, authentication, key);
  }

}
