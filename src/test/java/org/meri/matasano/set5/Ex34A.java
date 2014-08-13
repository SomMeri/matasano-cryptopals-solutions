package org.meri.matasano.set5;

import java.math.BigInteger;

import org.meri.matasano.utils.oracle.DynamicIVInCiphertextAESCBC;
import org.meri.matasano.utils.protocols.DiffieHellman;
import org.meri.matasano.utils.protocols.DiffieHellmanConversation;
import org.meri.matasano.utils.protocols.KeyPair;

public class Ex34A {

  private final DiffieHellmanConversation friend;

  public Ex34A(DiffieHellmanConversation friend) {
    this.friend = friend;
  }

  public byte[] talk(int p, int g, byte[] message) {
    DiffieHellman diffieHellman = new DiffieHellman(p, g);
    KeyPair aA = diffieHellman.generateKeyPair();
    BigInteger B = friend.initConversation(diffieHellman.getP(), diffieHellman.getG(), aA.getPublicKey());
    
    byte[] sessionKey = diffieHellman.sessionKeyWith(aA, B);
    DynamicIVInCiphertextAESCBC cipher  = new DynamicIVInCiphertextAESCBC(sessionKey);
    
    byte[] answer = friend.sendMessageExpectAnswer(cipher.encrypt(message));
    return cipher.decrypt(answer);
  }

}

