package org.meri.matasano.utils.encryption;

public class PadValidatingAESCBC extends AESCBC {
  
  private PkcsN7Padding padding = new PkcsN7Padding();

  public PadValidatingAESCBC() {
  }

  public byte[] decrypt(byte[] ciphertext, final byte[] key, byte[] iv) {
    CBC cbc = new CBC();
    byte[] paddedPlaintext = cbc.decrypt(ciphertext, iv, new AES(key));
    byte[] plaintext = padding.validateAndremovePadding(paddedPlaintext);
    return plaintext;
  }

}
