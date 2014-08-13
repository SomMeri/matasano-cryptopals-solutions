package org.meri.matasano.utils.networking;

import java.math.BigInteger;
import java.util.Arrays;

import jexxus.common.Connection;
import jexxus.common.Delivery;

import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.protocols.SRPClient;
import org.meri.matasano.utils.protocols.SRPServer;

public class NetworkedSRPClient implements SRPClient {

  private Connection connection;
  private final ArrayManips arrayManips = new ArrayManips();

  public NetworkedSRPClient(Connection connection) {
    this.connection = connection;
  }

  public void authenticateYourself(SRPServer server) {
    throw new IllegalStateException("This should not be called on netwroked instance.");
  }

  public void takeMySaltAndPublicKey(SRPServer server, byte[] salt, BigInteger B) {
    System.out.println("---- Sending salt and public key");
    System.out.println("Salt: " + Arrays.toString(salt));
    System.out.println("Public key: " + B);
    byte[] message = arrayManips.join(new byte[] {NetworkedSRPConstants.S_C_TAKE_MY_SALT_AND_PUBLIC_KEY, (byte) salt.length }, salt, B.toByteArray());
    connection.send(message, Delivery.RELIABLE);
  }

  public void takeMySaltAndPublicKey(SRPServer simpleSRPServerMath, byte[] salt, BigInteger B, BigInteger u) {
    System.out.println("---- Sending salt, public key and random u");
    System.out.println("Salt: " + Arrays.toString(salt));
    System.out.println("Public key: " + B);
    System.out.println("u: " + u);
    byte[] message = arrayManips.join(new byte[] {NetworkedSRPConstants.S_C_TAKE_MY_SALT_AND_PUBLIC_KEY_AND_U, (byte) salt.length }, salt, B.toByteArray(), u.toByteArray());
    connection.send(message, Delivery.RELIABLE);
   
  }

}
