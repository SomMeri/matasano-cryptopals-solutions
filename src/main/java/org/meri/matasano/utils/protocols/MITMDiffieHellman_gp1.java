package org.meri.matasano.utils.protocols;

import java.math.BigInteger;

import org.meri.matasano.utils.oracle.DynamicIVInCiphertextAESCBC;

public class MITMDiffieHellman_gp1 implements DiffieHellmanConversation  {
  
  private final DiffieHellmanConversation intendedFriendB;
  private byte[] interceptedMessage = null;
  private byte[] sessionKeyWithB;
  private DynamicIVInCiphertextAESCBC cipherB;
  
  public MITMDiffieHellman_gp1(DiffieHellmanConversation intendedFriend) {
    this.intendedFriendB = intendedFriend;
  }

  public BigInteger initConversation(BigInteger p, BigInteger g, BigInteger publicKey) {
    if (!g.equals(p.add(BigInteger.valueOf(-1))))
      throw new IllegalArgumentException("Attack works only for g=p-1");
    
    BigInteger intendedPublicKey = intendedFriendB.initConversation(p, g, publicKey);
    
    DiffieHellman diffieHellman = new DiffieHellman(1, 1);
    sessionKeyWithB = diffieHellman.convertToKey(publicKey);
    cipherB  = new DynamicIVInCiphertextAESCBC(sessionKeyWithB);

    
    return intendedPublicKey;
  }

  public byte[] sendMessageExpectAnswer(byte[] message) {
    byte[] ciphertext = intendedFriendB.sendMessageExpectAnswer(message);
    interceptedMessage = decrypt(ciphertext);
    return ciphertext;
  }

  public byte[] getInterceptedMessage() {
    return interceptedMessage;
  }

  private byte[] decrypt(byte[] ciphertext) {
    return cipherB.decrypt(ciphertext);
  }

}
