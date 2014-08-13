package org.meri.matasano.utils.oracle;

import org.meri.matasano.utils.encryption.AESCTR;

public class CipherEditingAESCTROracle {
  
  private AESCTR aesCtr = new AESCTR();
  private final byte[] key;
  
  public CipherEditingAESCTROracle(byte[] key) {
    this.key = key;
  }

  public byte[] edit(byte[] ciphertext, int offset, byte[] newtext) {
    return aesCtr.edit(ciphertext, key, offset, newtext);
  }

}
