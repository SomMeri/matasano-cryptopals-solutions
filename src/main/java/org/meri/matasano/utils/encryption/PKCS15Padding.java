package org.meri.matasano.utils.encryption;

import java.util.Arrays;

import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.RandomUtils;
import org.meri.matasano.utils.encryption.RSA.RSAPublicKey;

public class PKCS15Padding {
  
  private final RandomUtils random = new RandomUtils();
  private final ArrayManips manips = new ArrayManips();
  
  public byte[] padPkcs15(byte[] raw, RSAPublicKey publicKey) {
    return padPkcs15(raw, publicKey.getN().toByteArray().length);
  }
  
  public byte[] padPkcs15(byte[] raw, int blockLength) {
    byte[] prefix = new byte[] {0,2};
    byte[] random = randomArray(blockLength-raw.length-3);
    byte[] zero = new byte[] {0};
    return manips.join(prefix, random, zero, raw);
  }

  private byte[] randomArray(int length) {
    byte[] result = random.getExactBytes(length);
    for (int i = 0; i < result.length; i++) {
      if (result[i]==0)
        result[i]=1;
    }
    return result;
  }

  public byte[] removePadding(byte[] raw) {
    int start = 2;
    while (raw[start]!=0 && start<raw.length) {
      start++;
    }
    
    start++;
    if (start>=raw.length)
      throw new IllegalArgumentException("The input was not padded correctly.");
    
    return Arrays.copyOfRange(raw, start, raw.length);
  }

}
