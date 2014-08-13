package org.meri.matasano.utils.cryptoanalysis;

import java.math.BigInteger;

import org.meri.matasano.utils.protocols.SRPClient;
import org.meri.matasano.utils.protocols.SRPMath;
import org.meri.matasano.utils.protocols.SRPServer;

public abstract class FakeASRPClientMath implements SRPClient {

  private String identifier;
  
  private final SRPMath srpMath = new SRPMath();

  public FakeASRPClientMath(BigInteger N, BigInteger g, BigInteger k, String identifier, String password) {
    this.identifier = identifier;
  }

  public void authenticateYourself(SRPServer server) {
    server.logMeIn(this, identifier, getFakeA());
  }

  protected abstract BigInteger getFakeA();

  public void takeMySaltAndPublicKey(SRPServer server, byte[] salt, BigInteger B) {
    // Generate S = (B - k * g**x)**(a + u * x) % N
    BigInteger S = BigInteger.ZERO;

    byte[] K = srpMath.kFomS(S);
    server.validateHMACSHA(this, srpMath.hmacSha1(K, salt));
  }

  public void takeMySaltAndPublicKey(SRPServer simpleSRPServerMath, byte[] salt, BigInteger b, BigInteger u) {
    throw new IllegalStateException("The method is compatible only with simple client.");
  }


}
