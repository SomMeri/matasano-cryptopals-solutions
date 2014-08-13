package org.meri.matasano.utils.encryption;

public class AESCBC {
  
  private PkcsN7Padding padding = new PkcsN7Padding();

  public AESCBC() {
  }

  public byte[] decrypt(byte[] ciphertext, final byte[] key, byte[] iv) {
    CBC cbc = new CBC();
    byte[] paddedPlaintext = cbc.decrypt(ciphertext, iv, new AES(key));
    byte[] plaintext = padding.removePadding(paddedPlaintext);
    return plaintext;
  }

  public byte[] encrypt(byte[] plaintext, final byte[] key, byte[] iv) {
    AES coreCipher = new AES(key);
    byte[] paddedPlaintext = padding.padPkcsN7(plaintext, coreCipher.getBlockLength());
    
    CBC cbc = new CBC();
    byte[] ciphertext = cbc.encrypt(paddedPlaintext, iv, coreCipher);
    return ciphertext;
  }

  public int getBlockSize() {
    return 16;
  }

}
