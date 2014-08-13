package org.meri.matasano.utils.cryptoanalysis;

import java.util.Arrays;

import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.encryption.SHA1;
import org.meri.matasano.utils.oracle.ConstantKeyAuthenticator;

public class SHA1Forgerer {

  private ArrayManips arrayManips = new ArrayManips();

  public Forgery addSuffix(ConstantKeyAuthenticator authenticator, byte[] originalMessage, byte[] originalMessageAuthentication, byte[] fakeSuffix) {
    for (int keyLength = 0; keyLength < 1000; keyLength++) {
      Forgery forgery = addSuffix(keyLength, originalMessage, originalMessageAuthentication, fakeSuffix);
      if (authenticator.validate(forgery.getMessage(), forgery.getAuthentication()))
        return forgery;
    }
    throw new IllegalStateException("Such big key is unlikely, something is wrong.");
  }

  private Forgery addSuffix(int keyLength, byte[] originalMessage, byte[] originalMessageAuthentication, byte[] fakeSuffix) {
    byte[] suffix = simulateFirstByteIntegerPosition(fakeSuffix);

    int[] abcde = arrayManips.bitewiseToIntegers(originalMessageAuthentication);
    int suffixLength = (suffix.length) * 8;

    byte[] fmIncludingKey = simulateFullForgedMessage(keyLength, originalMessage, suffix);
    byte[] fmWithoutKey = cutOutKey(keyLength, fmIncludingKey);
    int lengthInBites = (fmIncludingKey.length) * 8;
    byte[] forged = SHA1.encode(suffix, abcde[0], abcde[1], abcde[2], abcde[3], abcde[4], lengthInBites - suffixLength);

    return new Forgery(fmWithoutKey, forged);
  }

  private byte[] cutOutKey(int keyLength, byte[] forgedMessageIncludingKeyInBytes) {
    return Arrays.copyOfRange(forgedMessageIncludingKeyInBytes, keyLength, forgedMessageIncludingKeyInBytes.length);
  }

  private byte[] simulateFullForgedMessage(int keyLength, byte[] originalMessage, byte[] suffix) {
    int[] paddedMessage = SHA1.toPaddedIntegerArray(arrayManips.join(new byte[keyLength], originalMessage), 0);
    int[] forgedMessageIncludingKey = arrayManips.join(paddedMessage, arrayManips.bitewiseToIntegers(suffix));
    byte[] forgedMessageIncludingKeyInBytes = arrayManips.bitewiseToBytes(forgedMessageIncludingKey);
    return forgedMessageIncludingKeyInBytes;
  }

  private byte[] simulateFirstByteIntegerPosition(byte[] customSuffix) {
    int prefixLength = (4 - (customSuffix.length % 4) % 4);
    return arrayManips.join(new byte[prefixLength], customSuffix);
  }

}
