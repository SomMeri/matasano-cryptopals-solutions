package org.meri.matasano.utils.protocols;

import java.math.BigInteger;

public interface SRPServer {

  public void logMeIn(SRPClient client, String identifier, BigInteger A);

  public void validateHMACSHA(SRPClient client, byte[] authentication);
}
