package org.meri.matasano.utils.protocols;

import java.math.BigInteger;

import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.encryption.HMAC;
import org.meri.matasano.utils.encryption.SHA1;
import org.meri.matasano.utils.encryption.Sha1HMAC;

public class SRPMath {

  private final ArrayManips arrayManips = new ArrayManips();

  private byte[] saltedPasswordHash(byte[] salt, String password) {
    return SHA1.encode(arrayManips.join(salt, password.getBytes()));
  }

  public BigInteger saltedPasswordHashX(byte[] salt, String password) {
    return new BigInteger(saltedPasswordHash(salt, password));
  }

  public byte[] kFomS(BigInteger S) {
    return SHA1.encode(S.toByteArray());
  }

  public BigInteger u(BigInteger A, BigInteger B) {
    byte[] uH = SHA1.encode(arrayManips.join(A.toByteArray(), B.toByteArray())) ;
    BigInteger u = new BigInteger(uH);
    return u;
  }

  public byte[] hmacSha1(byte[] K, byte[] salt) {
    HMAC hmac = new Sha1HMAC();
    return hmac.generateAuthentication(K, salt);
  }

}
