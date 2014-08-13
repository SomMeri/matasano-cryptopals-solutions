package org.meri.matasano.utils.networking;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import jexxus.common.Connection;
import jexxus.server.Server;

import org.meri.matasano.utils.protocols.SRPClient;
import org.meri.matasano.utils.protocols.SRPServer;

public class SRPLoginService {

  private final SRPServer underlyingServer;
  private Server tcpServer;

  public SRPLoginService(SRPServer underlyingServer, int portNumber) {
    super();
    tcpServer = new Server(new SRPLoginServiceConnectionListener(), portNumber);
    this.underlyingServer = underlyingServer;
  }

  public void start() {
    tcpServer.startServer();
  }

  class SRPLoginServiceConnectionListener extends SysoutConnectionListener {
    private Map<Connection, SRPClient> clientsMap = new HashMap<Connection, SRPClient>();

    public void receive(byte[] data, Connection from) {
      if (data[0] == NetworkedSRPConstants.C_S_LOG_ME_IN_CODE) {
        int indentifierLength = data[1];
        String identifier = new String(Arrays.copyOfRange(data, 2, 2 + indentifierLength));
        BigInteger A = new BigInteger(Arrays.copyOfRange(data, 2 + indentifierLength, data.length));
        System.out.println("---- recieved request to log in");
        System.out.println("Identifier: " + identifier);
        System.out.println("Public key: " + A);
        
        NetworkedSRPClient client = new NetworkedSRPClient(from);
        clientsMap.put(from, client);
        underlyingServer.logMeIn(client, identifier, A);
      } else if (data[0] == NetworkedSRPConstants.C_S_VALIDATE_HMAC_SHA256) {
        byte[] hmac = Arrays.copyOfRange(data, 1, data.length);
        System.out.println("---- Recieved hmac for validation");
        System.out.println("HMAC: " + Arrays.toString(hmac));
        underlyingServer.validateHMACSHA(clientsMap.get(from), hmac);
        System.out.println("---- Validation probably succesfull - no exception thrown from method.");
      } else {
        System.out.println("SRPLoginService received unexpected data: " + data);
      }
    }

  }
}
