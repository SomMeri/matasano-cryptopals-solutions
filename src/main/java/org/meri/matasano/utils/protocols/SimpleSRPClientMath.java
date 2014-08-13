package org.meri.matasano.utils.protocols;

import java.math.BigInteger;

public class SimpleSRPClientMath implements SRPClient {

  private BigInteger N;
  private BigInteger g;
  private String identifier;
  private String password;
  private BigInteger A;
  
  private final SRPMath srpMath = new SRPMath();
  private BigInteger a;

  public SimpleSRPClientMath(BigInteger N, BigInteger g, String identifier, String password) {
    this.N = N;
    this.g = g;
    this.identifier = identifier;
    this.password = password;
  }

  public void authenticateYourself(SRPServer server) {
    DiffieHellman diffieHellman = new DiffieHellman(N, g);
    KeyPair keyPair = diffieHellman.generateKeyPair();
    a = keyPair.getPrivateKey();
    A = keyPair.getPublicKey();
    server.logMeIn(this, identifier, A);
  }

  public void takeMySaltAndPublicKey(SRPServer server, byte[] salt, BigInteger B) {
    throw new IllegalStateException("Method is not compatible with simple client.");
  }
  
  public void takeMySaltAndPublicKey(SRPServer server, byte[] salt, BigInteger B, BigInteger u) {
    BigInteger x = srpMath.saltedPasswordHashX(salt, password) ;

    // Generate S = (B)**(a + u * x) % N
    BigInteger S = B.modPow(a.add(u.multiply(x)), N);

    byte[] K = srpMath.kFomS(S);
    server.validateHMACSHA(this, srpMath.hmacSha1(K, salt));
  }

  
}
