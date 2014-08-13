package org.meri.matasano.utils.protocols;

import java.math.BigInteger;

public class SRPAuthenticationData {

  public BigInteger N;
  public BigInteger g;
  public BigInteger k;
  public String identifier;
  public byte[] salt;
  public BigInteger v;
  public BigInteger u;

  public SRPAuthenticationData(BigInteger N, BigInteger g, BigInteger k, String identifier, byte[] salt, BigInteger v) {
    this.N = N;
    this.g = g;
    this.k = k;
    this.identifier = identifier;
    this.salt = salt;
    this.v = v;
  }

  
}