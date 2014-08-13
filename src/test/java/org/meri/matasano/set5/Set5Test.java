package org.meri.matasano.set5;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;

import org.junit.Test;
import org.meri.matasano.Set5;
import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.cryptoanalysis.SRPClientMath_A0;
import org.meri.matasano.utils.cryptoanalysis.SRPClientMath_A2N;
import org.meri.matasano.utils.cryptoanalysis.SRPClientMath_AN;
import org.meri.matasano.utils.cryptoanalysis.SimpleSRPManInTheMiddle;
import org.meri.matasano.utils.encryption.RSA;
import org.meri.matasano.utils.encryption.RSA.RSAPublicKey;
import org.meri.matasano.utils.networking.NetworkedSRPServer;
import org.meri.matasano.utils.networking.SRPLoginService;
import org.meri.matasano.utils.protocols.DiffieHellman;
import org.meri.matasano.utils.protocols.KeyPair;
import org.meri.matasano.utils.protocols.MITMDiffieHellman_g1;
import org.meri.matasano.utils.protocols.MITMDiffieHellman_gp;
import org.meri.matasano.utils.protocols.MITMDiffieHellman_gp1;
import org.meri.matasano.utils.protocols.MITMDiffieHellman_p;
import org.meri.matasano.utils.protocols.SRPClient;
import org.meri.matasano.utils.protocols.SRPClientMath;
import org.meri.matasano.utils.protocols.SRPServerMath;
import org.meri.matasano.utils.protocols.SimpleSRPClientMath;
import org.meri.matasano.utils.protocols.SimpleSRPServerMath;

public class Set5Test {
  private static final String EX_33_P_STR = "2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919";
  @SuppressWarnings("unused")
  private static final String EX_33_P_HEX = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
  private static final BigInteger EX_33_G = BigInteger.valueOf(2);


  private Set5 set = new Set5();
  private ArrayManips arrayManips = new ArrayManips();

  @Test
  public void ex33_small() {
    DiffieHellman diffieHellman = new DiffieHellman(37,5);

    KeyPair aA = diffieHellman.generateKeyPair();
    KeyPair bB = diffieHellman.generateKeyPair();

    byte[] sBa = diffieHellman.sessionKeyWith(aA, bB.getPublicKey());
    byte[] sAb = diffieHellman.sessionKeyWith(bB, aA.getPublicKey());

    assertArrayEquals(sBa, sAb);
  }

  @Test
  public void ex33_big() {
    // the encoded number seems to be negative from java
    // so I decoded it in rubymonk and passed to java as decimal string
    BigInteger p = new BigInteger(EX_33_P_STR);
    assertTrue(p.isProbablePrime(50));
    DiffieHellman diffieHellman = new DiffieHellman(p,EX_33_G);

    KeyPair aA = diffieHellman.generateKeyPair();
    KeyPair bB = diffieHellman.generateKeyPair();

    byte[] sBa = diffieHellman.sessionKeyWith(aA, bB.getPublicKey());
    byte[] sAb = diffieHellman.sessionKeyWith(bB, aA.getPublicKey());

    assertArrayEquals(sBa, sAb);
  }

  @Test
  public void ex34_unmodified() {
    Ex33EchoBot echo = new Ex33EchoBot();
    Ex34A A = new Ex34A(echo);
    byte[] message = arrayManips.createInitializedArray(12, 12);
    byte[] response = A.talk(37, 5, message);

    assertArrayEquals(message, response);
  }

  @Test
  public void ex34_mitm() {
    Ex33EchoBot echo = new Ex33EchoBot();
    MITMDiffieHellman_p mitm = new MITMDiffieHellman_p(echo);
    Ex34A A = new Ex34A(mitm);
    byte[] message = arrayManips.createInitializedArray(12, 12);
    byte[] response = A.talk(37, 2, message);

    assertArrayEquals(message, response);
    assertArrayEquals(message, mitm.getInterceptedMessage());
  }

  @Test
  public void ex35_g1() {
    Ex33EchoBot echo = new Ex33EchoBot();
    MITMDiffieHellman_g1 mitm = new MITMDiffieHellman_g1(echo);
    Ex34A A = new Ex34A(mitm);
    byte[] message = arrayManips.createInitializedArray(12, 12);
    byte[] response = A.talk(37, 1, message);

    assertArrayEquals(message, response);
    assertArrayEquals(message, mitm.getInterceptedMessage());
  }

  @Test
  public void ex35_gp() {
    Ex33EchoBot echo = new Ex33EchoBot();
    MITMDiffieHellman_gp mitm = new MITMDiffieHellman_gp(echo);
    Ex34A A = new Ex34A(mitm);
    byte[] message = arrayManips.createInitializedArray(12, 12);
    byte[] response = A.talk(37, 37, message);

    assertArrayEquals(message, response);
    assertArrayEquals(message, mitm.getInterceptedMessage());
  }

  @Test
  public void ex35_gp1() {
    Ex33EchoBot echo = new Ex33EchoBot();
    MITMDiffieHellman_gp1 mitm = new MITMDiffieHellman_gp1(echo);
    Ex34A A = new Ex34A(mitm);
    byte[] message = arrayManips.createInitializedArray(12, 12);
    byte[] response = A.talk(37, 37 - 1, message);

    assertArrayEquals(message, response);
    assertArrayEquals(message, mitm.getInterceptedMessage());
  }

  @Test
  public void ex36() {
    SRPServerMath server = new SRPServerMath();

    BigInteger N = new BigInteger(EX_33_P_STR);
    BigInteger g = BigInteger.valueOf(2);
    BigInteger k=BigInteger.valueOf(3);
    String I = "foo@gmail.com";
    String P = "supersecretpassword";
    
    server.createNewUser(N, g, k, I, P);

    SRPClient client = new SRPClientMath(N, g, k, I, P);
    client.authenticateYourself(server);
    assertTrue(server.isAuthenticated());
  }

  @Test(timeout=5000)
  public void ex37_actual_network() {
    // shared values
    BigInteger N = new BigInteger(EX_33_P_STR);
    BigInteger g = BigInteger.valueOf(2);
    BigInteger k=BigInteger.valueOf(3);
    String I = "foo@gmail.com";
    String P = "supersecretpassword";
    
    // init server
    SRPServerMath server = startNetworkedSRPServer(N, g, k, I, P, 33333);
    
    // log into the service
    SRPClient client = new SRPClientMath(N, g, k, I, P);
    client.authenticateYourself(new NetworkedSRPServer("localhost", 33333));
    
    // Wait until they done communicating and check the result. The test will
    // fail on timeout if something is wrong. 
    waitTillAuthenticated(server);
  }

  /**
   * If A is zero, the value of S is zero too.
   * 
   */
  @Test(timeout=5000)
  public void ex37_hack_A0() {
    // shared values
    BigInteger N = new BigInteger(EX_33_P_STR);
    BigInteger g = BigInteger.valueOf(2);
    BigInteger k=BigInteger.valueOf(3);
    String I = "foo@gmail.com";
    String P = "supersecretpassword";
    
    // init server
    SRPServerMath server = startNetworkedSRPServer(N, g, k, I, P, 33334);
    
    // log into the service
    SRPClient client = new SRPClientMath_A0(N, g, k, I, P);
    client.authenticateYourself(new NetworkedSRPServer("localhost", 33334));
    
    // Wait until they done communicating and check the result. The test will
    // fail on timeout if something is wrong. 
    waitTillAuthenticated(server);
  }

  /**
   * If A is a multiple of N, the value of S is zero.
   * 
   */
  @Test(timeout=5000)
  public void ex37_hack_AN() {
    // shared values
    BigInteger N = new BigInteger(EX_33_P_STR);
    BigInteger g = BigInteger.valueOf(2);
    BigInteger k=BigInteger.valueOf(3);
    String I = "foo@gmail.com";
    String P = "supersecretpassword";
    
    // init server
    SRPServerMath server = startNetworkedSRPServer(N, g, k, I, P, 33335);
    
    // log into the service
    SRPClient client = new SRPClientMath_AN(N, g, k, I, P);
    client.authenticateYourself(new NetworkedSRPServer("localhost", 33335));
    
    // Wait until they done communicating and check the result. The test will
    // fail on timeout if something is wrong. 
    waitTillAuthenticated(server);
  }

  /**
   * If A is a multiple of N, the value of S is zero.
   * 
   */
  @Test(timeout=5000)
  public void ex37_hack_A2N() {
    // shared values
    BigInteger N = new BigInteger(EX_33_P_STR);
    BigInteger g = BigInteger.valueOf(2);
    BigInteger k=BigInteger.valueOf(3);
    String I = "foo@gmail.com";
    String P = "supersecretpassword";
    
    // init server
    SRPServerMath server = startNetworkedSRPServer(N, g, k, I, P, 33336);
    
    // log into the service
    SRPClient client = new SRPClientMath_A2N(N, g, k, I, P);
    client.authenticateYourself(new NetworkedSRPServer("localhost", 33336));
    
    // Wait until they done communicating and check the result. The test will
    // fail on timeout if something is wrong. 
    waitTillAuthenticated(server);
  }

  @Test
  public void ex38_no_middle_man() {
    SimpleSRPServerMath server = new SimpleSRPServerMath();

    BigInteger N = new BigInteger(EX_33_P_STR);
    BigInteger g = BigInteger.valueOf(2);
    String I = "foo@gmail.com";
    String P = "supersecretpassword";
    
    server.createNewUser(N, g, I, P);

    SimpleSRPClientMath client = new SimpleSRPClientMath(N, g, I, P);
    client.authenticateYourself(server);
    assertTrue(server.isAuthenticated());
  }
  
  @Test
  public void ex38_offline_attack() {
    BigInteger N = new BigInteger(EX_33_P_STR);
    BigInteger g = BigInteger.valueOf(2); 
    String I = "foo@gmail.com";
    String P = "password";
    
    SimpleSRPServerMath server = new SimpleSRPServerMath();
    server.createNewUser(N, g, I, P);

    SimpleSRPManInTheMiddle manInTheMiddle = new SimpleSRPManInTheMiddle(N, g); 
    
    SimpleSRPClientMath client = new SimpleSRPClientMath(N, g, I, P);
    client.authenticateYourself(manInTheMiddle);
    String cracked = manInTheMiddle.crackPassword();
    assertEquals(P, cracked);
  }

  @Test
  public void ex39() {
    RSA rsa = new RSA();
    String message = "password";
    byte[] ciphertext = rsa.encrypt(message.getBytes());
    byte[] decrypt = rsa.decrypt(ciphertext);
    
    assertEquals(message, new String(decrypt));
  }

  @Test
  public void ex40() {
    String message = "broadcasted secret";

    RSA rsa1 = new RSA();
    byte[] ciphertext1 = rsa1.encrypt(message.getBytes());
    RSAPublicKey publicKey1 = rsa1.getPublicKey();

    RSA rsa2 = new RSA();
    byte[] ciphertext2 = rsa2.encrypt(message.getBytes());
    RSAPublicKey publicKey2 = rsa2.getPublicKey();

    RSA rsa3 = new RSA();
    byte[] ciphertext3 = rsa3.encrypt(message.getBytes());
    RSAPublicKey publicKey3 = rsa3.getPublicKey();
    
    String cracked = set.crackE3RSA(ciphertext1, publicKey1, ciphertext2, publicKey2, ciphertext3, publicKey3);
    assertEquals(message, cracked);
  }

  private void waitTillAuthenticated(SRPServerMath server) {
    while (!server.isAuthenticated()) {
      try {
        Thread.sleep(100);
      } catch (InterruptedException e) {
        throw new RuntimeException(e);
      }
    }
  }

  private SRPServerMath startNetworkedSRPServer(BigInteger N, BigInteger g, BigInteger k, String I, String P, int portNumber) {
    SRPServerMath server = new SRPServerMath();
    server.createNewUser(N, g, k, I, P);

    SRPLoginService actualNetworkServer = new SRPLoginService(server, portNumber);
    actualNetworkServer.start();
    return server;
  }

}

