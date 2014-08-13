package org.meri.matasano.utils.cryptoanalysis;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Iterator;

import org.meri.matasano.utils.DummyDictionary;
import org.meri.matasano.utils.protocols.SRPClient;
import org.meri.matasano.utils.protocols.SRPMath;
import org.meri.matasano.utils.protocols.SRPServer;

public class SimpleSRPManInTheMiddle implements SRPServer {

  private final SRPMath srpMath = new SRPMath();
  private final byte[] salt = new byte[0];
  private BigInteger A;
  private BigInteger g;
  private byte[] authentication;
  private BigInteger N;

  public SimpleSRPManInTheMiddle(BigInteger N, BigInteger g) {
    this.N = N;
    this.g = g;
  }

  public void logMeIn(SRPClient client, String identifier, BigInteger A) {
    this.A = A;
    client.takeMySaltAndPublicKey(this, salt, g, BigInteger.ONE);
  }

  public void validateHMACSHA(SRPClient client, byte[] authentication) {
    this.authentication = authentication;
    // pretend validation fail, this is man in the middle
  }

  public boolean isAuthenticated() {
    return false;
  }

  public String crackPassword() {
    Iterator<String> words = DummyDictionary.DICTIONARY.iterator();
    while (words.hasNext()) {
      String guess = words.next();
      if (isCorrect(guess))
        return guess;

    }
    return null;
  }

  private boolean isCorrect(String guess) {
    BigInteger x = srpMath.saltedPasswordHashX(salt, guess);
    BigInteger S = A.multiply(g.modPow(x, N)).mod(N);

    byte[] K = srpMath.kFomS(S);
    byte[] hmacSha1 = srpMath.hmacSha1(K, salt);
    return Arrays.equals(authentication, hmacSha1);
  }

}
