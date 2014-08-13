package org.meri.matasano.utils.protocols;

import java.math.BigInteger;

public interface DiffieHellmanConversation {

  public abstract BigInteger initConversation(BigInteger p, BigInteger g, BigInteger publicKey);

  public abstract byte[] sendMessageExpectAnswer(byte[] message);

}