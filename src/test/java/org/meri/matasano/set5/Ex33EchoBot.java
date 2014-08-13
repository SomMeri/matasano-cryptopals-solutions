package org.meri.matasano.set5;

import java.math.BigInteger;

import org.meri.matasano.utils.oracle.DynamicIVInCiphertextAESCBC;
import org.meri.matasano.utils.protocols.DiffieHellman;
import org.meri.matasano.utils.protocols.DiffieHellmanConversation;
import org.meri.matasano.utils.protocols.KeyPair;

public class Ex33EchoBot implements DiffieHellmanConversation {

  private byte[] sessionKey;
  private KeyPair keyPair;
  private DiffieHellman diffieHellman;
  private DynamicIVInCiphertextAESCBC cipher;

  public Ex33EchoBot() {
  }

  public BigInteger initConversation(BigInteger p, BigInteger g, BigInteger publicKey) {
    diffieHellman = new DiffieHellman(p, g);
    keyPair = diffieHellman.generateKeyPair();
    sessionKey = diffieHellman.sessionKeyWith(keyPair, publicKey);
    cipher  = new DynamicIVInCiphertextAESCBC(sessionKey);

    return keyPair.getPublicKey();
  }

  public byte[] sendMessageExpectAnswer(byte[] message) {
    byte[] plaintext = cipher.decrypt(message);
    return cipher.encrypt(plaintext);
  }

}