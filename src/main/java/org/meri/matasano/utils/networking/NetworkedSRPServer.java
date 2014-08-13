package org.meri.matasano.utils.networking;

import java.math.BigInteger;
import java.util.Arrays;

import jexxus.client.ClientConnection;
import jexxus.common.Connection;
import jexxus.common.Delivery;

import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.protocols.SRPClient;
import org.meri.matasano.utils.protocols.SRPServer;

public class NetworkedSRPServer implements SRPServer {

  private String hostname;
  private int portNumber;
  private ArrayManips arrayManips = new ArrayManips();
  private ClientConnection connection;

  public NetworkedSRPServer(String hostname, int portNumber) {
    this.hostname = hostname;
    this.portNumber = portNumber;
  }

  public void logMeIn(SRPClient client, String identifier, BigInteger A) {
    connection = connect(client);
    System.out.println("---- sending log in request");
    System.out.println("Identifier: " + identifier);
    System.out.println("Public key: " + A);

    byte[] identifierBytes = identifier.getBytes();
    byte[] message = arrayManips.join(new byte[] { NetworkedSRPConstants.C_S_LOG_ME_IN_CODE, (byte) identifierBytes.length }, identifierBytes, A.toByteArray());
    connection.send(message, Delivery.RELIABLE);
  }

  public void validateHMACSHA(SRPClient client, byte[] authentication) {
    if (connection==null || !connection.isConnected())
      throw new IllegalStateException("Connection to server died.");
    
    byte[] message = arrayManips.join(new byte[] { NetworkedSRPConstants.C_S_VALIDATE_HMAC_SHA256 }, authentication);
    System.out.println("---- Sending hash mac for validation");
    System.out.println("HMAC: " + Arrays.toString(authentication));
    connection.send(message, Delivery.RELIABLE);
  }

  private ClientConnection connect(SRPClient client) {
    try {
      ClientConnection conn = new ClientConnection(new NetworkedSRPServerConnectionListener(client, this), hostname, portNumber);
      conn.connect();
      return conn;
    } catch (Throwable th) {
      throw new IllegalStateException(th);
    }
  }

  class NetworkedSRPServerConnectionListener extends SysoutConnectionListener {

    private SRPClient client;
    private SRPServer server;

    public NetworkedSRPServerConnectionListener(SRPClient client, SRPServer server) {
      this.client = client;
      this.server = server;
    }

    public void receive(byte[] data, Connection from) {
      if (data[0] == NetworkedSRPConstants.S_C_TAKE_MY_SALT_AND_PUBLIC_KEY) {
        int saltLength = data[1];

        byte[] salt = Arrays.copyOfRange(data, 2, 2 + saltLength);
        BigInteger B = new BigInteger(Arrays.copyOfRange(data, 2 + saltLength, data.length));
        System.out.println("---- Recieved salt and public key");
        System.out.println("Salt: " + Arrays.toString(salt));
        System.out.println("Public key: " + B);
        client.takeMySaltAndPublicKey(server, salt, B);
      } else if (data[0] == NetworkedSRPConstants.S_C_TAKE_MY_SALT_AND_PUBLIC_KEY_AND_U) {
        int saltLength = data[1];

        byte[] salt = Arrays.copyOfRange(data, 2, 2 + saltLength);
        BigInteger B = new BigInteger(Arrays.copyOfRange(data, 2 + saltLength, data.length-16));
        BigInteger u = new BigInteger(Arrays.copyOfRange(data, data.length-16, data.length));
        System.out.println("---- Recieved salt, public key and u");
        System.out.println("Salt: " + Arrays.toString(salt));
        System.out.println("Public key: " + B);
        System.out.println("u: " + u);
        client.takeMySaltAndPublicKey(server, salt, B, u);
      } else{
        System.out.println("NetworkedSRPServer received unexpected data: " + new String(data));
      }
    }

  }
}
