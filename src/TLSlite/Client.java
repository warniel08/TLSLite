package TLSlite;

import javax.crypto.*;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
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

public class Client {
    // initialize socket and input output streams
    Socket socket;

    // constructor to put ip address and port
    public Client(String address, int port) throws IOException {
        // establish a connection
        try {
            socket = new Socket(address, port);
            System.out.println("Connected");

            String SHA256wRSA = "SHA256WithRSA";

            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            // KeyFactory generation
            KeyFactory kf = KeyFactory.getInstance("RSA");
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            // Certs creation
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

            // Client Private Key
            byte[] clientKeyBytes = Files.readAllBytes(Paths.get("src/TLSlite/keys/clientPrivateKey.der"));
            PKCS8EncodedKeySpec clientSpec = new PKCS8EncodedKeySpec(clientKeyBytes);
            PrivateKey clientPK = kf.generatePrivate(clientSpec);

            //=====================================================================
            //                         START HANDSHAKE
            //=====================================================================

            // Create nonce
            SecureRandom clientNonce = new SecureRandom();
            byte[] nonce = new byte[32];
            clientNonce.nextBytes(nonce);

            // send nonce to server
            oos.writeObject(nonce);
            // write to baos
            baos.write(nonce);

            // receive server cert
            Certificate servCert = (Certificate) ois.readObject();
            // write server cert to baos to be stored for later
            baos.write(servCert.getEncoded());

            // verify server cert
            try {
                servCert.verify(CACertificate.getPublicKey());
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException |
                    CertificateException e) {
                e.printStackTrace();
            }

            // Generate random for rClient/rServer generation
            Random rand = new Random();

            // Generate client DH pub key
            BigInteger rClient = new BigInteger(256, rand);
            BigInteger Tc = new BigInteger(String.valueOf(2)).modPow(rClient, N);

            // receive server's DH pub key
            BigInteger Ts = (BigInteger) ois.readObject();
            // write server's DH pub key to baos
            baos.write(Ts.toByteArray());

            // Shared DH pub key using server's DH pub key
            BigInteger sharedDHSecKey = Ts.modPow(rClient, N);
//            System.out.println("sharedDHSecKey: " + sharedDHSecKey);

            // receive server signed DH pub key
            byte[] serverSignedDHPubKey = (byte[]) ois.readObject();
            // write server signed DH pub key to baos
            baos.write(serverSignedDHPubKey);
            System.out.println("server signed dh pub key received");

            // Client cert gen
            InputStream clientCertificateInputStream = new FileInputStream("src/TLSlite/keys/CAClientCertificate.pem");
            Certificate clientCertificate = certificateFactory.generateCertificate(clientCertificateInputStream);

            // send cert
            oos.writeObject(clientCertificate);
            // write to baos
            baos.write(clientCertificate.getEncoded());

            // Send client DH Public Key
            oos.writeObject(Tc);
            // write to baos
            baos.write(Tc.toByteArray());

            // Random gen for signature setup
            SecureRandom secureRandom = new SecureRandom();

            // Client signature obj gen
            Signature clientSignatureObj = Signature.getInstance(SHA256wRSA);
            byte[] clientSignedDHPubKey = Main.getDigitalSignature(clientPK, Tc, secureRandom, clientSignatureObj);

            // Send client signed dh pub key
            oos.writeObject(clientSignedDHPubKey);
            // write to baos
            baos.write(clientSignedDHPubKey);
            System.out.println("client signed dh pub key sent");

            // Server signature verify
            boolean servVerify = Main.isSignatureVerify(Ts, servCert, clientSignatureObj, serverSignedDHPubKey);
            System.out.println("server verify: " + servVerify);

            //=====================================================================
            //                     END FIRST PART OF HANDSHAKE
            //=====================================================================

            // Session keys from shared dh secret
            Main.makeSecretKeys(nonce, sharedDHSecKey.toByteArray());

            // shared dh secret key generation using serverMac
            Mac cliServHandshakeMac = Main.getMac(Main.serverMAC);
            byte[] cliServMacMessages = cliServHandshakeMac.doFinal(baos.toByteArray());

            // receive serverMacMessages
            byte[] serverMacMessages = (byte[]) ois.readObject();
            // write server mac messages to baos
            baos.write(serverMacMessages);

            if (Arrays.equals(cliServMacMessages, serverMacMessages)) {
                System.out.println("Mac messages are the same");
            } else {
                System.out.println("Mac messages are NOT the same");
                socket.close();
            }

            // shared dh secret key generation using clientMac
            Mac clientHandshakeMac = Main.getMac(Main.clientMAC);
            byte[] clientMacMessages = clientHandshakeMac.doFinal(baos.toByteArray());

            // send clientMacMessages to server
            oos.writeObject(clientMacMessages);

            //=====================================================================
            //                           FINISH HANDSHAKE
            //=====================================================================

            // store large file to test against received file
            byte[] warAndPeace = Files.readAllBytes(Paths.get("src/TLSlite/warAndPeace.txt"));
            int wnpLength = warAndPeace.length;

            // receive book
            byte[] cipherTextData1 = (byte[]) ois.readObject();
            baos.write(cipherTextData1);
            byte[] cipherTextData2 = (byte[]) ois.readObject();
            baos.write(cipherTextData2);

            // create cipher object
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // initialize cipher
            cipher.init(Cipher.DECRYPT_MODE, Main.serverEncryptKey, Main.serverIVSpec);
            // decrypt the data
            byte[] decryptedText1 = cipher.update(cipherTextData1);
            byte[] decryptedText2 = cipher.doFinal(cipherTextData2);

            ByteArrayOutputStream bookOS = new ByteArrayOutputStream();
            bookOS.write(decryptedText1);
            bookOS.write(decryptedText2);

            byte[] decryptedBook = bookOS.toByteArray();

            if (Arrays.equals(warAndPeace, decryptedBook)) {
                System.out.println("decrypted book and orig book ARE same");
            } else
                System.out.println("decrypted book and orig book are NOT same");

            String ack = "Got the book, thanks!";
            byte[] ackBytes = ack.getBytes();

            // initialize cipher for ack
            cipher.init(Cipher.ENCRYPT_MODE, Main.clientEncryptKey, Main.clientIVSpec);
            // encrypt the data
            byte[] ackCipherText = cipher.doFinal(ackBytes);

            String s = new String(ackCipherText);
            System.out.println("Encrypted message for server: " + s);

            // send acknowledgement message back to server
            oos.writeObject(ackCipherText);
            baos.write(ackCipherText);

            // close the client connection
            System.out.println("Closing client connection...");
            socket.close();
        } catch (UnknownHostException | NoSuchAlgorithmException | CertificateException | InvalidKeySpecException |
                InvalidKeyException | SignatureException | ClassNotFoundException | NoSuchPaddingException |
                InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws IOException {
        Client client = new Client("127.0.0.1", 9000);
    }
}