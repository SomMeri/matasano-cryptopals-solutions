package org.meri.matasano.utils.encryption;

import java.util.Arrays;

import org.meri.matasano.utils.ArrayManips;

/*
 * A Java implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS PUB 180-1
 * Copyright (C) Sam Ruby 2004
 * All rights reserved
 *
 * Based on code Copyright (C) Paul Johnston 2000 - 2002.
 * See http://pajhome.org.uk/site/legal.html for details.
 *
 * Converted to Java by Russell Beattie 2004
 * Base64 logic and inlining by Sam Ruby 2004
 * Bug fix correcting single bit error in base64 code by John Wilson
 *
 *                                BSD License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer. Redistributions in binary
 * form must reproduce the above copyright notice, this list of conditions and
 * the following disclaimer in the documentation and/or other materials
 * provided with the distribution.
 *
 * Neither the name of the author nor the names of its contributors may be
 * used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

public class SHA1 {

  private static final int DEFAULT_E = -1009589776;
  private static final int DEFAULT_D = 271733878;
  private static final int DEFAULT_C = -1732584194;
  private static final int DEFAULT_B = -271733879;
  private static final int DEFAULT_A = 1732584193;

  /*
   * Bitwise rotate a 32-bit number to the left
   */
  private static int rol(int num, int cnt) {
    return (num << cnt) | (num >>> (32 - cnt));
  }

  public static byte[] encode(byte[] input) {
    int[] blks = toPaddedIntegerArray(input, 0);
    int[] words = encodePaddedInts(blks, DEFAULT_A, DEFAULT_B, DEFAULT_C, DEFAULT_D, DEFAULT_E);
    return (new ArrayManips()).bitewiseToBytes(words);
  }

  public static byte[] encode(byte[] input, int a, int b, int c, int d, int e, int addToLength) {
    int[] blks = toPaddedIntegerArray(input, addToLength);
    int[] words = encodePaddedInts(blks, a, b, c, d, e);
    return (new ArrayManips()).bitewiseToBytes(words);
  }

  // calculate 160 bit SHA1 hash of the sequence of blocks
  private static int[] encodePaddedInts(int[] blks, int a, int b, int c, int d, int e) {

    for (int i = 0; i < blks.length; i += 16) {
      int[] w = new int[80];
      int olda = a;
      int oldb = b;
      int oldc = c;
      int oldd = d;
      int olde = e;

      for (int j = 0; j < 80; j++) {
        w[j] = (j < 16) ? blks[i + j] : (rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1));

        int t = rol(a, 5) + e + w[j] + ((j < 20) ? 1518500249 + ((b & c) | ((~b) & d)) : (j < 40) ? 1859775393 + (b ^ c ^ d) : (j < 60) ? -1894007588 + ((b & c) | (b & d) | (c & d)) : -899497514 + (b ^ c ^ d));
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = t;
      }

      a = a + olda;
      b = b + oldb;
      c = c + oldc;
      d = d + oldd;
      e = e + olde;
    }
    int[] words = { a, b, c, d, e };
    return words;
  }

  public static int[] toPaddedIntegerArray(byte[] input, int addToLength) {
    ArrayManips arrayManips = new ArrayManips();
    int[] ints = arrayManips.bitewiseToIntegers(input);
    
    
    // Convert an input to a sequence of 16-word blocks, stored as an array.
    // Append padding bits and the length, as described in the SHA1 standard
    int blksLength = (((input.length + 8) >> 6) + 1) * 16;
    int[] blks = Arrays.copyOf(ints, blksLength);//new int[blksLength];
    
    int idx = input.length >> 2;
    int currentPos=input.length; 
    blks[idx] = ((blks[idx] << 8) | (0x80)) << ((3 - (currentPos & 3)) << 3);
    blks[blks.length - 1] = (input.length * 8) + addToLength;
    return blks;
  }

}