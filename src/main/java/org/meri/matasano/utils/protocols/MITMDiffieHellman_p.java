package org.meri.matasano.utils.protocols;

import java.math.BigInteger;

import org.meri.matasano.utils.oracle.DynamicIVInCiphertextAESCBC;

public class MITMDiffieHellman_p implements DiffieHellmanConversation  {
  
  private final DiffieHellmanConversation intendedFriend;
  private byte[] interceptedMessage = null;
  private byte[] sessionKey;
  private DynamicIVInCiphertextAESCBC cipher;
  
  public MITMDiffieHellman_p(DiffieHellmanConversation intendedFriend) {
    this.intendedFriend = intendedFriend;
  }

  public BigInteger initConversation(BigInteger p, BigInteger g, BigInteger publicKey) {
    DiffieHellman diffieHellman = new DiffieHellman(1, 1);
    sessionKey = diffieHellman.convertToKey(BigInteger.valueOf(0));
    cipher  = new DynamicIVInCiphertextAESCBC(sessionKey);

    intendedFriend.initConversation(p, g, p);
    return p;
  }

  public byte[] sendMessageExpectAnswer(byte[] message) {
    byte[] ciphertext = intendedFriend.sendMessageExpectAnswer(message);
    interceptedMessage = decrypt(ciphertext);
    return ciphertext;
  }

  public byte[] getInterceptedMessage() {
    return interceptedMessage;
  }

  private byte[] decrypt(byte[] ciphertext) {
    return cipher.decrypt(ciphertext);
  }

}
