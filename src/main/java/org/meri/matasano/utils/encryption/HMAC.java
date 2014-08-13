package org.meri.matasano.utils.encryption;

import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.Xor;

public abstract class HMAC {
  
  private ArrayManips arrayManips = new ArrayManips();
  private Xor xor = new Xor();

  public byte[] generateAuthentication(byte[] message, byte[] key) {
    if (key.length > getBlocksize()) {
      key = hash(key); 
    }
    if (key.length < getBlocksize()) {
      key = xor.xorDontWrap(key, new byte[getBlocksize()]);
    }
    
    byte[] oPad = xor.xorDontWrap(arrayManips.createInitializedArray(getBlocksize(), 0x5c), key);
    byte[] iPad = xor.xorDontWrap(arrayManips.createInitializedArray(getBlocksize(), 0x36), key);
    byte[] iContent = hash(arrayManips.join(iPad, message));
    byte[] result = hash(arrayManips.join(oPad, iContent));
    return result;
  }

  protected abstract byte[] hash(byte[] key);
  protected abstract int getBlocksize();
  
}
