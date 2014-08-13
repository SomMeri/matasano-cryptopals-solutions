package org.meri.matasano.utils.encryption;

import java.util.Arrays;


public class IncrementalNonce {
  
  private final int emptyPrefixLength;
  private final int nonceLength;
  
  private byte[] current;

  public IncrementalNonce(int emptyPrefixLength, int nonceLength) {
    this(emptyPrefixLength, defaultNonce(emptyPrefixLength,nonceLength));
  }

  private static byte[] defaultNonce(int emptyPrefixLength, int nonceLength) {
    byte[] result = new byte[nonceLength];
    result[0]=0;
    return result;
  }

  public IncrementalNonce(int emptyPrefixLength, byte[] initialNonce) {
    super();
    this.emptyPrefixLength = emptyPrefixLength;
    this.nonceLength = emptyPrefixLength + initialNonce.length;
    this.current = new byte[nonceLength];
    System.arraycopy(initialNonce, 0, current, emptyPrefixLength, initialNonce.length);
  }

  public IncrementalNonce increment() {
    for (int i=emptyPrefixLength; i<nonceLength; i++) {
      if (current[i]!=Byte.MAX_VALUE) {
        current[i]++;
        return this;
      } 
      current[i]=0;
    }
    
    throw new IllegalStateException("Nonce is completely full.");
  }
  
  public byte[] getBytes() {
    return current;
  }

  @Override
  public String toString() {
    return "IncrementalNonce " + Arrays.toString(current) + "";
  }
  
  
}
