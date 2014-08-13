package org.meri.matasano.utils.cryptoanalysis;

import org.meri.matasano.utils.oracle.PaddingRSAOracle;

public interface IBleichenbacher98 {

  public byte[] decryptRSAPaddingOracle(byte[] ciphertext, PaddingRSAOracle oracle);

  public boolean hadMultiple();

}