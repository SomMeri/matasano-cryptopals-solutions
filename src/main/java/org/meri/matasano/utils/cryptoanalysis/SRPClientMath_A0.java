package org.meri.matasano.utils.cryptoanalysis;

import java.math.BigInteger;

public class SRPClientMath_A0 extends FakeASRPClientMath {

  public SRPClientMath_A0(BigInteger N, BigInteger g, BigInteger k, String identifier, String password) {
    super(N, g, k, identifier, password);
  }

  @Override
  protected BigInteger getFakeA() {
    return BigInteger.ZERO;
  }

}