package org.meri.matasano.utils.protocols;

import java.math.BigInteger;

public class SRPClientMath implements SRPClient {

  private BigInteger N;
  private BigInteger g;
  private BigInteger k;
  private String identifier;
  private String password;
  private BigInteger A;
  
  private final SRPMath srpMath = new SRPMath();
  private BigInteger a;

  public SRPClientMath(BigInteger N, BigInteger g, BigInteger k, String identifier, String password) {
    this.N = N;
    this.g = g;
    this.k = k;
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
    BigInteger u = srpMath.u(A, B);
    BigInteger x = srpMath.saltedPasswordHashX(salt, password) ;

    // Generate S = (B - k * g**x)**(a + u * x) % N
    BigInteger S = B.add(k.multiply(g.modPow(x, N)).negate()).modPow(a.add(u.multiply(x)), N);

    byte[] K = srpMath.kFomS(S);
    server.validateHMACSHA(this, srpMath.hmacSha1(K, salt));
  }

  public void takeMySaltAndPublicKey(SRPServer simpleSRPServerMath, byte[] salt, BigInteger b, BigInteger u) {
    throw new IllegalStateException("Method is compatible only with simple client.");
  }

  
}
