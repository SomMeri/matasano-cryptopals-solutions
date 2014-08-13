package org.meri.matasano;

import java.math.BigInteger;

import org.meri.matasano.utils.cryptoanalysis.CRT;
import org.meri.matasano.utils.encryption.RSA.RSAPublicKey;

public class Set5 {

  private static final BigInteger THREE = BigInteger.valueOf(3);
  private static final BigInteger TWO = BigInteger.valueOf(2);

  /**
   * Exercise 40
   */
  public String crackE3RSA(byte[] ciphertext1, RSAPublicKey publicKey1, byte[] ciphertext2, RSAPublicKey publicKey2, byte[] ciphertext3, RSAPublicKey publicKey3) {
    BigInteger[] constraints = new BigInteger[] { new BigInteger(ciphertext1), new BigInteger(ciphertext2), new BigInteger(ciphertext3) };
    BigInteger[] mods = new BigInteger[] { publicKey1.getN(), publicKey2.getN(), publicKey3.getN() };
    BigInteger M = publicKey1.getN().multiply(publicKey2.getN().multiply(publicKey3.getN()));
    BigInteger crt = CRT.crt(constraints, mods, M);
    BigInteger messageNumber = cubeRoot(crt, 500);

    return new String(messageNumber.toByteArray());
  }

  public BigInteger cubeRoot(BigInteger B, int iter) {
    BigInteger[] cubique = new BigInteger[2];
    cubique[0] = B.divide(THREE);
    for (int i = 0; i < iter; i++) {
      cubique[1] = ((cubique[0].multiply(TWO)).add(B.divide(cubique[0].pow(2)))).divide(THREE);
      cubique[0] = cubique[1];
    }
    return cubique[0];
  }

}
