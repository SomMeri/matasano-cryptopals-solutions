package org.meri.matasano.utils.encryption;

import java.util.Arrays;

public class PkcsN7Padding {

  public byte[] padPkcsN7(byte[] raw, int blockLength) {
    int fullBlocks = raw.length / blockLength;

    int paddedLenth = (fullBlocks + 1) * blockLength;
    int padding = paddedLenth - raw.length;
    byte[] result = Arrays.copyOf(raw, paddedLenth);
    Arrays.fill(result, raw.length, result.length, (byte) padding);
    return result;
  }

  public byte[] removePadding(byte[] raw) {
    byte paddingLength = raw[raw.length - 1];
    if (raw.length - paddingLength<0)
      return raw;
    
    return Arrays.copyOf(raw, raw.length - paddingLength);
  }

  public byte[] validateAndremovePadding(byte[] raw) throws InvalidPaddingException {
    byte paddingLength = raw[raw.length - 1];
    if (paddingLength < 1)
      throw new InvalidPaddingException();

    byte idx = paddingLength;
    while (idx > 0) {
      if (raw.length < idx)
        throw new InvalidPaddingException();
      
      if (raw[raw.length - idx] != paddingLength)
        throw new InvalidPaddingException();
      idx--;
    }

    return removePadding(raw);
  }

  @SuppressWarnings("serial")
  public class InvalidPaddingException extends RuntimeException {

  }

}
