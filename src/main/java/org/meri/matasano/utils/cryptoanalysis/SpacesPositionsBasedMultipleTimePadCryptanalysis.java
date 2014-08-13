package org.meri.matasano.utils.cryptoanalysis;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.meri.matasano.utils.Ascii;
import org.meri.matasano.utils.Xor;

public class SpacesPositionsBasedMultipleTimePadCryptanalysis {

  private Ascii ascii = new Ascii();
  private Xor xor = new Xor();

  public byte[] recoverMostOfTheKey(List<byte[]> ciphers) {
    byte[] key = new byte[100]; // not a proper initialization
    
    for (byte[] outer : ciphers) {
      Set<Integer> spaces = createConsecutiveNumbersSet(outer.length);

      for (byte[] inner : ciphers)
        if (outer != inner) {
          byte[] combined = xor.xorDontWrap(outer, inner);
          for (int i = 0; i < combined.length; i++) {
            if (!ascii.isEnglishCharacter(combined[i]) & !spaceXorSpecial(combined[i])){
              spaces.remove(i);
            } 
          }
        }
      recoverKeyPart(key, spaces, outer);
    }
    return key;
  }

  private void recoverKeyPart(byte[] key, Set<Integer> spaces, byte[] ciphertext) {
    for (int position : spaces) {
      key[position] = (byte)(ciphertext[position] ^ ' ');
    }
  }

  private Set<Integer> createConsecutiveNumbersSet(int max) {
    Set<Integer> spaces = new HashSet<Integer>();
    for (int i = 0; i < max; i++)
      spaces.add(i);
    return spaces;
  }

  private boolean spaceXorSpecial(byte combined) {
    return 0 == combined || ((byte) '.' ^ (byte) ' ') == combined || ((byte) '/' ^ (byte) ' ') == combined || ((byte) ',' ^ (byte) ' ') == combined || ((byte) '!' ^ (byte) ' ') == combined || ((byte) '-' ^ (byte) ' ') == combined || ((byte) ':' ^ (byte) ' ') == combined || ((byte) '\'' ^ (byte) ' ') == combined || ((byte) '?' ^ (byte) ' ') == combined || ((byte) ';' ^ (byte) ' ') == combined || ((byte) '\n' ^ (byte) ' ') == combined;
  }

}
