package org.meri.matasano.utils.webtools;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Date;

import org.apache.shiro.codec.CodecSupport;
import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.encryption.ShortKeyMersenneTwisterCTR;

public class PasswordResetTokenManager {

  private static final byte[] SIGNATURE = CodecSupport.toBytes("generated from password reset token generator");

  private ArrayManips arrayUtils = new ArrayManips();
  private ShortKeyMersenneTwisterCTR cipher = new ShortKeyMersenneTwisterCTR();

  public byte[] generatePasswordResetToken() {
    byte[] token = arrayUtils.join(getRandomBytes(), SIGNATURE);
    return cipher.encrypt(token, (int) (new Date()).getTime());
  }

  public boolean isPasswordResetToken(byte[] token) {
    if (token.length <= SIGNATURE.length)
      return false;

    for (int guess = 0; guess < ShortKeyMersenneTwisterCTR.RELEVANT_KEY_BITS; guess++) {
      byte[] plaintext = cipher.decrypt(token, guess);
      byte[] signature = Arrays.copyOfRange(plaintext, plaintext.length - SIGNATURE.length, plaintext.length);
      if (Arrays.equals(signature, SIGNATURE))
        return true;
    }

    return false;
  }

  private byte[] getRandomBytes() {
    SecureRandom realRandomGenerator = new SecureRandom();
    byte[] result = new byte[Math.abs(realRandomGenerator.nextInt()) % 256];
    realRandomGenerator.nextBytes(result);

    return result;
  }
}
