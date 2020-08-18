package TLSlite;

import javax.crypto.*;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;

public class Server {
    //initialize socket
    Socket socket;
    ServerSocket server;

    // constructor with port
    public Server(int port) {
        // starts server and waits for a connection
        try {
            server = new ServerSocket(port);
            System.out.println("Server started");

            System.out.println("Waiting for a client ...");

            socket = server.accept();
            System.out.println("Client accepted");

            String SHA256wRSA = "SHA256WithRSA";

            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            // KeyFactory generation
            KeyFactory kf = KeyFactory.getInstance("RSA");
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            // Cert Creation
            InputStream CACertificateInputStream = new FileInputStream("src/TLSlite/keys/CAcertificate.pem");
            Certificate CACertificate = certificateFactory.generateCertificate(CACertificateInputStream);

            String modp2048 = (
                    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1" +
                            "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD" +
                            "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245" +
                            "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED" +
                            "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D" +
                            "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F" +
                            "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D" +
                            "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B" +
                            "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9" +
                            "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510" +
                            "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF")
                    .replaceAll("\\s", "");

            BigInteger N = new BigInteger(modp2048, 16);

            // Server Private Key
            byte[] serverKeyBytes = Files.readAllBytes(Paths.get("src/TLSlite/keys/serverPrivateKey.der"));
            PKCS8EncodedKeySpec serverSpec = new PKCS8EncodedKeySpec(serverKeyBytes);
            PrivateKey serverPK = kf.generatePrivate(serverSpec);

            //=====================================================================
            //                         START HANDSHAKE
            //=====================================================================

            // receive nonce from client
            byte[] nonce = (byte[]) ois.readObject();
            // write nonce to baos
            baos.write(nonce);

            // Server cert gen
            InputStream serverCertificateInputStream = new FileInputStream("src/TLSlite/keys/CASignedServerCertificate.pem");
            Certificate serverCertificate = certificateFactory.generateCertificate(serverCertificateInputStream);

            // send server cert
            oos.writeObject(serverCertificate);
            // write to baos
            baos.write(serverCertificate.getEncoded());

            // Generate random for rServer/Client calculation
            Random rand = new Random();

            BigInteger rServer = new BigInteger(256, rand);
            BigInteger Ts = new BigInteger(String.valueOf(2)).modPow(rServer, N);

            // Send server DH Public Key
            oos.writeObject(Ts);
            // write to baos
            baos.write(Ts.toByteArray());

            // Random gen for signature setup
            SecureRandom secureRandom = new SecureRandom();

            // Server signature obj gen
            Signature serverSignatureObj = Signature.getInstance(SHA256wRSA);
            byte[] serverSignedDHPubKey = Main.getDigitalSignature(serverPK, Ts, secureRandom, serverSignatureObj); // send to client

            // Send server signed dh pub key
            oos.writeObject(serverSignedDHPubKey);
            // write to baos
            baos.write(serverSignedDHPubKey);
            System.out.println("server signed dh pub key sent");

            // receive client cert
            Certificate clientCert = (Certificate) ois.readObject();
            // write client cert to baos
            baos.write(clientCert.getEncoded());

            // verify client cert
            try {
                clientCert.verify(CACertificate.getPublicKey());
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException |
                    CertificateException e) {
                e.printStackTrace();
            }

            // receive client's DH pub key
            BigInteger Tc = (BigInteger) ois.readObject();
            // write client's DH pub key to baos
            baos.write(Tc.toByteArray());

            // Shared DH public key using client's DH pub key
            BigInteger sharedDHSecKey = Tc.modPow(rServer, N);
//            System.out.println("sharedDHSecKey: " + sharedDHSecKey);

            // receive client signed DH pub key
            byte[] clientSignedDHSecKey = (byte[]) ois.readObject();
            // write client signed DH pub key to baos
            baos.write(clientSignedDHSecKey);
            System.out.println("client signed dh pub key received");

            // Client signature verify
            boolean clientVerify = Main.isSignatureVerify(Tc, clientCert, serverSignatureObj, clientSignedDHSecKey);
            System.out.println("client verify: " + clientVerify);

            //=====================================================================
            //                      END FIRST PART OF HANDSHAKE
            //=====================================================================

            // Session keys from shared dh secret
            Main.makeSecretKeys(nonce, sharedDHSecKey.toByteArray());

            // shared dh secret key generation for server
            Mac serverHandshakeMac = Main.getMac(Main.serverMAC);
            byte[] serverMacMessages = serverHandshakeMac.doFinal(baos.toByteArray());

            // send serverMacMessages
            oos.writeObject(serverMacMessages);
            // write to baos
            baos.write(serverMacMessages);

            // receive clientMacMessages
            byte[] clientMacMessages = (byte[]) ois.readObject();

            // shared dh secret key generation for server
            Mac servCliHandshakeMac = Main.getMac(Main.clientMAC);
            byte[] servCliMacMessages = servCliHandshakeMac.doFinal(baos.toByteArray());

            if (Arrays.equals(clientMacMessages, servCliMacMessages)) {
                System.out.println("Mac messages are the same");
            } else {
                System.out.println("Mac messages are NOT the same");
                socket.close();
            }

            //=====================================================================
            //                           FINISH HANDSHAKE
            //=====================================================================


            // Beginning of sending large message
            byte[] warAndPeace = Files.readAllBytes(Paths.get("src/TLSlite/warAndPeace.txt"));

            byte[] firstHalfOfBook = Arrays.copyOfRange(warAndPeace, 0, warAndPeace.length/2);
            byte[] secondHalfOfBook = Arrays.copyOfRange(warAndPeace, firstHalfOfBook.length, warAndPeace.length);

            // create cipher object
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // initialize cipher
            cipher.init(Cipher.ENCRYPT_MODE, Main.serverEncryptKey, Main.serverIVSpec);
            // encrypt the data
            byte[] cipherText1 = cipher.update(firstHalfOfBook);
            byte[] cipherText2 = cipher.doFinal(secondHalfOfBook);

            // send book
            oos.writeObject(cipherText1);
            baos.write(cipherText1);
            oos.writeObject(cipherText2);
            baos.write(cipherText2);

            // receive acknowledgement message
            byte[] cipherAckData = (byte[]) ois.readObject();
            baos.write(cipherAckData);

            String s = new String(cipherAckData);
            System.out.println("Encrypted message from client: " + s);

            // initialize cipher
            cipher.init(Cipher.DECRYPT_MODE, Main.clientEncryptKey, Main.clientIVSpec);
            // decrypt the data
            byte[] cipherAckText = cipher.doFinal(cipherAckData);
            String ret = new String(cipherAckText);
            System.out.println("Decrypted message from client: " + ret);

            // close server connection
            System.out.println("Closing server connection...");
            socket.close();
        } catch(IOException | NoSuchAlgorithmException | CertificateException | InvalidKeySpecException |
                SignatureException | InvalidKeyException | ClassNotFoundException | NoSuchPaddingException |
                InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        Server server = new Server(9000);
    }
}