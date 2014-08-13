package org.meri.matasano.utils.protocols;

import java.math.BigInteger;

public interface SRPClient {
  
  public void authenticateYourself(SRPServer server);

  public void takeMySaltAndPublicKey(SRPServer server, byte[] salt, BigInteger B);

  public void takeMySaltAndPublicKey(SRPServer simpleSRPServerMath, byte[] salt, BigInteger b, BigInteger u);

}
