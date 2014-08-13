package org.meri.matasano.utils.cryptoanalysis;

import org.apache.shiro.codec.CodecSupport;

public class Hamming {
  
  public int distance(String first, String second) {
    return distance(CodecSupport.toBytes(first), CodecSupport.toBytes(second));
  }

  public int distance(byte[] first, byte[] second) {
    int minLength = Math.min(first.length, second.length);
    int maxLength = Math.max(first.length, second.length);

    int result = 0;
    for (int i = 0; i < minLength; i++) {
      int xor = first[i] ^ second[i];
      result+=Integer.bitCount(xor);
    }
    
    result+=8*(maxLength-minLength);
    
    return result;
  }

  public double normalizedDistance(byte[] first, byte[] second) {
    int distance = distance(first, second);
    int maxLength = Math.max(first.length, second.length);

    return (double)distance/(double)maxLength;
  }
}
