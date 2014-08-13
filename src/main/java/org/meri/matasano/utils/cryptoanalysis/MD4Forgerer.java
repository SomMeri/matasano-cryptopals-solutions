package org.meri.matasano.utils.cryptoanalysis;

import java.util.Arrays;

import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.encryption.MD4;
import org.meri.matasano.utils.oracle.ConstantKeyAuthenticator;

public class MD4Forgerer {

  private ArrayManips arrayManips = new ArrayManips();

  public Forgery addSuffix(ConstantKeyAuthenticator authenticator, byte[] originalMessage, byte[] originalMessageAuthentication, byte[] fakeSuffix) {
    for (int keyLength = 0; keyLength < 1000; keyLength++) {
      Forgery forgery = addSuffix(keyLength, originalMessage, originalMessageAuthentication, fakeSuffix, 0);
      if (authenticator.validate(forgery.getMessage(), forgery.getAuthentication()))
        return forgery;
    }
    throw new IllegalStateException("Such big key is unlikely, something is wrong.");
  }

  private Forgery addSuffix(int keyLength, byte[] originalMessage, byte[] originalMessageAuthentication, byte[] fakeSuffix, int prefix) {
    byte[] suffix = simulateFirstByteIntegerPosition(fakeSuffix, prefix);

    int[] abcde = arrayManips.bitewiseToIntegersBigEnd(originalMessageAuthentication);

    byte[] fmIncludingKey = simulateFullForgedMessage(keyLength, originalMessage, suffix);
    byte[] fmWithoutKey = cutOutKey(keyLength, fmIncludingKey);
    MD4 md4 = new MD4(abcde[0], abcde[1], abcde[2], abcde[3]);
    
    md4.update(suffix);
    byte[] forged = md4.digest(fmIncludingKey.length - suffix.length);


    return new Forgery(fmWithoutKey, forged);
  }

  private byte[] cutOutKey(int keyLength, byte[] forgedMessageIncludingKeyInBytes) {
    return Arrays.copyOfRange(forgedMessageIncludingKeyInBytes, keyLength, forgedMessageIncludingKeyInBytes.length);
  }

  private byte[] simulateFullForgedMessage(int keyLength, byte[] originalMessage, byte[] suffix) {
    byte[] keyMessage = arrayManips.join(new byte[keyLength], originalMessage);
    byte[] paddedMessage = addPadding(keyMessage);
    byte[] forgedMessageIncludingKey = arrayManips.join(paddedMessage, suffix);
  
    return forgedMessageIncludingKey;
  }

  private byte[] addPadding(byte[] keyMessage) {
    MD4 md4 = new MD4();
    md4.update(keyMessage);
    byte[] padding = md4.pad(0);
    byte[] paddedMessage = arrayManips.join(keyMessage, padding);
    return paddedMessage;
  }

  private byte[] simulateFirstByteIntegerPosition(byte[] customSuffix, int prefix) {
    // return customSuffix;
    int prefixLength = (4 - (customSuffix.length % 4) % 4);
    prefixLength = prefix;
    return arrayManips.join(new byte[prefixLength], customSuffix);
  }

}
