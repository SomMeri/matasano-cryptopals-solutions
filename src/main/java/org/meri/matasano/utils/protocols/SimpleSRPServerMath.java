package org.meri.matasano.utils.protocols;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import org.meri.matasano.utils.RandomUtils;

public class SimpleSRPServerMath implements SRPServer {

  private final SRPMath srpMath = new SRPMath();
  private final RandomUtils randomUtils = new RandomUtils();
  
  private SRPAuthenticationData data;
  private BigInteger A;
  private BigInteger b;
  private boolean isAuthenticated;
  private BigInteger B;

  public SimpleSRPServerMath() {

  }

  public void createNewUser(BigInteger N, BigInteger g, String identifier, String password) {
    // create salt
    SecureRandom random = new SecureRandom();
    byte[] salt = new byte[] { (byte) random.nextInt() };

    // calculate v
    BigInteger x = srpMath.saltedPasswordHashX(salt, password);
    BigInteger v = g.modPow(x, N);

    // create authentication data object
    this.data = new SRPAuthenticationData(N, g, null, identifier, salt, v);
    this.data.u = new BigInteger(randomUtils.getExactBytes(16));
  }

  public void logMeIn(SRPClient client, String identifier, BigInteger A) {
    if (!this.data.identifier.equals(identifier))
      throw new IllegalArgumentException("Wrong account name.");

    this.A = A;

    DiffieHellman diffieHellman = new DiffieHellman(data.N, data.g);
    KeyPair bB = diffieHellman.generateKeyPair();//FIXME: change to normal random

    b = bB.getPrivateKey();
    B = data.g.modPow(b, data.N);
    client.takeMySaltAndPublicKey(this, data.salt, B, data.u);

  }

  public void validateHMACSHA(SRPClient client, byte[] authentication) {
    // Generate S = (A * v**u) ** b % N
    BigInteger S = A.multiply(data.v.modPow(data.u, data.N)).modPow(b, data.N);
    byte[] K = srpMath.kFomS(S);

    byte[] expectedAuthentication = srpMath.hmacSha1(K, data.salt);
    if (Arrays.equals(expectedAuthentication, authentication))
      isAuthenticated = true;
    else {
      throw new IllegalAccessError();
    }
  }

  public boolean isAuthenticated() {
    return isAuthenticated;
  }

}
