package org.meri.matasano.utils;

import org.apache.shiro.codec.Hex;

public class Xor {

  public byte[] xor(byte[] first, byte[] second) {
    byte[] shorter = first;
    byte[] longer = second;
    if (longer.length < shorter.length) {
      shorter = second;
      longer = first;
    }

    byte[] result = new byte[longer.length];
    for (int i = 0; i < longer.length; i++) {
      result[i] = (byte) (longer[i] ^ shorter[i % shorter.length]);
    }
    return result;
  }

  public byte[] xorDontWrap(byte[] first, byte[] second) {
    byte[] shorter = first;
    byte[] longer = second;
    if (longer.length < shorter.length) {
      shorter = second;
      longer = first;
    }

    byte[] result = new byte[shorter.length];
    for (int i = 0; i < shorter.length; i++) {
      result[i] = (byte) (longer[i] ^ shorter[i % shorter.length]);
    }
    return result;
  }

  public String xorHex(String first, String second) {
    return Hex.encodeToString(xor(Hex.decode(first), Hex.decode(second)));
  }

  public byte[] xor(byte[] input, char key) {
    byte[] keyAsArray = new byte[] { (byte) key };
    return xor(input, keyAsArray);
  }

}
