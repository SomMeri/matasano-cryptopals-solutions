package org.meri.matasano.utils.cryptoanalysis;

import java.math.BigInteger;

public class SRPClientMath_A2N extends FakeASRPClientMath {

  private BigInteger N;

  public SRPClientMath_A2N(BigInteger N, BigInteger g, BigInteger k, String identifier, String password) {
    super(N, g, k, identifier, password);
    this.N = N;
  }

  @Override
  protected BigInteger getFakeA() {
    return N.multiply(BigInteger.valueOf(2));
  }

}