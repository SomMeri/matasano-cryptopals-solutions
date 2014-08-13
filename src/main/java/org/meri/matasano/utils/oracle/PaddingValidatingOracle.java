package org.meri.matasano.utils.oracle;

public interface PaddingValidatingOracle {

  public boolean validatePadding(byte[] ciphertext);

  public int getBlockLength();

}
