package org.meri.matasano.utils.encryption;

import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.crypto.OperationMode;
import org.apache.shiro.crypto.PaddingScheme;
import org.apache.shiro.util.ByteSource;


public class AESECB {
  
  private PkcsN7Padding padding = new PkcsN7Padding();

  public AESECB() {
  }

  public byte[] decrypt(byte[] ciphertext, final byte[] key) {
    AesCipherService cipher = new AesCipherService();
    cipher.setMode(OperationMode.ECB);
    cipher.setPaddingScheme(PaddingScheme.NONE);
    
    ByteSource plaintext = cipher.decrypt(ciphertext, key);
    return padding.removePadding(plaintext.getBytes());
  }

  public byte[] encrypt(byte[] plaintext, final byte[] key) {
    AesCipherService cipher = new AesCipherService();
    cipher.setMode(OperationMode.ECB);
    cipher.setPaddingScheme(PaddingScheme.NONE);

    byte[] paddedPlaintext = padding.padPkcsN7(plaintext, getBlockSize());
    ByteSource ciphertext = cipher.encrypt(paddedPlaintext, key);
    return ciphertext.getBytes();
  }
  
  public int getBlockSize() {
    return 16;
  }

}
