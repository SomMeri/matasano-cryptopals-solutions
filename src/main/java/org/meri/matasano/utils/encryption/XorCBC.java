package org.meri.matasano.utils.encryption;


public class XorCBC {

  public byte[] decrypt(byte[] ciphertext, final byte[] key, byte[] iv) {
    CBC cbc = new CBC();
    byte[] plaintext = cbc.decrypt(ciphertext, iv, new ManyTimePad(key));

    return plaintext;
  }

  public byte[] encrypt(byte[] plaintext, final byte[] key, byte[] iv) {
    CBC cbc = new CBC();
    byte[] ciphertext = cbc.encrypt(plaintext, iv, new ManyTimePad(key));

    return ciphertext;
  }

}
