package org.meri.matasano.utils.encryption;

public interface CoreCipher {

  byte[] encrypt(byte[] plaintext);

  byte[] decrypt(byte[] ciphertext);

  int getBlockLength();

}
