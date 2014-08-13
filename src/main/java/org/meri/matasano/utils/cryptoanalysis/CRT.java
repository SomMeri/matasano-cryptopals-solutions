package org.meri.matasano.utils.cryptoanalysis;

import java.math.BigInteger;
//https://raw.github.com/GregOwen/Chinese-Remainder-Theorem/master/CRT.java
/*
 * Written By: Gregory Owen
 * Date: 10/10/11
 * Finds a single congruence equivalent to multiple given congruences
 * (assuming that one exists) via the Chinese Remainder Theorem
 */

public class CRT {
  /*
   * performs the Euclidean algorithm on a and b to find a pair of coefficients
   * (stored in the output array) that correspond to x and y in the equation
   * ax + by = gcd(a,b)
   * constraint: a > b
   */
  public static BigInteger[] euclidean(BigInteger a, BigInteger b) {
    if (b.min(a)==a) { // if (b>a)
      //reverse the order of inputs, run through this method, then reverse outputs
      BigInteger[] coeffs = euclidean(b, a);
      BigInteger[] output = { coeffs[1], coeffs[0] };
      return output;
    }

    BigInteger q = a.divide(b);
    //a = q*b + r --> r = a - q*b
    BigInteger r = a.add(q.multiply(b).negate());

    //when there is no remainder, we have reached the gcd and are done
    if (r.equals(BigInteger.ZERO)) {
      BigInteger[] output = { BigInteger.ZERO, BigInteger.ONE };
      return output;
    }

    //call the next iteration down (b = qr + r_2)
    BigInteger[] next = euclidean(b, r);

    BigInteger[] output = { next[1], next[0].add(q.multiply(next[1]).negate()) };
    return output;
  }

  //finds the least positive integer equivalent to a mod m
  public static BigInteger leastPosEquiv(BigInteger a, BigInteger m) {
    //a eqivalent to b mod -m <==> a equivalent to b mod m
    if (m.compareTo(BigInteger.ZERO) < 0)
      return leastPosEquiv(a, BigInteger.valueOf(-1).multiply(m));
    //if 0 <= a < m, then a is the least positive integer equivalent to a mod m
    if (a.compareTo(BigInteger.ZERO) >= 0 && a.compareTo(m) < 0)
      return a;

    //for negative a, find the least negative integer equivalent to a mod m
    //then add m
    if (a.compareTo(BigInteger.ZERO) < 0)
      return BigInteger.valueOf(-1).multiply(leastPosEquiv(BigInteger.valueOf(-1).multiply(a), m).add(m));

    //the only case left is that of a,m > 0 and a >= m

    //take the remainder according to the Division algorithm
    BigInteger q = a.divide(m);

    /*
     * a = qm + r, with 0 <= r < m
     * r = a - qm is equivalent to a mod m
     * and is the least such non-negative number (since r < m)
     */
    return a.add(q.multiply(m).negate());
  }

  public static void main(String[] args) {
    /*
     * the current setup finds a number x such that:
     *  x = 2 mod 5, x = 3 mod 7, x = 4 mod 9, and x = 5 mod 11
     * note that the values in mods must be mutually prime
     */
    BigInteger[] constraints = { BigInteger.valueOf(2), BigInteger.valueOf(3), BigInteger.valueOf(4), BigInteger.valueOf(5) }; //put modular contraints here
    BigInteger[] mods = { BigInteger.valueOf(5), BigInteger.valueOf(7), BigInteger.valueOf(9), BigInteger.valueOf(11) }; //put moduli here

    //M is the product of the mods
    BigInteger M = BigInteger.valueOf(1);
    for (int i = 0; i < mods.length; i++)
      M = M.multiply(mods[i]);

    //Exprected result x is equivalent to 1732 mod 6930
    //                 x is equivalent to 1732 mod 3465
    BigInteger x = crt(constraints, mods, M);

    System.out.println("x is equivalent to " + x + " mod " + M);
  }

  public static BigInteger crt(BigInteger[] constraints, BigInteger[] mods, BigInteger M) {
    BigInteger[] multInv = new BigInteger[constraints.length];

    /*
     * this loop applies the Euclidean algorithm to each pair of M/mods[i] and mods[i]
     * since it is assumed that the various mods[i] are pairwise coprime,
     * the end result of applying the Euclidean algorithm will be
     * gcd(M/mods[i], mods[i]) = 1 = a(M/mods[i]) + b(mods[i]), or that a(M/mods[i]) is
     * equivalent to 1 mod (mods[i]). This a is then the multiplicative
     * inverse of (M/mods[i]) mod mods[i], which is what we are looking to multiply
     * by our constraint constraints[i] as per the Chinese Remainder Theorem
     * euclidean(M/mods[i], mods[i])[0] returns the coefficient a
     * in the equation a(M/mods[i]) + b(mods[i]) = 1
     */
    for (int i = 0; i < multInv.length; i++) {
      BigInteger mi = mods[i];
      multInv[i] = euclidean(M.divide(mi), mi)[0];
    }

    BigInteger x = BigInteger.ZERO;

    //x = the sum over all given i of (M/mods[i])(constraints[i])(multInv[i])
    for (int i = 0; i < mods.length; i++) {
      x = x.add((M.divide(mods[i])).multiply(constraints[i].multiply(multInv[i])));
    }

    x = leastPosEquiv(x, M);
    return x.mod(M);
  }
}