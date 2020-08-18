package TLSlite;

import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;
import java.security.spec.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Random;

public class Main {
    static byte[] serverEncrypt;
    static byte[] clientEncrypt;
    static byte[] serverMAC;
    static byte[] clientMAC;
    static byte[] serverIV;
    static byte[] clientIV;

    static SecretKeySpec serverEncryptKey;
    static SecretKeySpec clientEncryptKey;
    static SecretKeySpec serverHMACKey;
    static SecretKeySpec clientHMACKey;
    static IvParameterSpec serverIVSpec;
    static IvParameterSpec clientIVSpec;

    static byte[] getDigitalSignature(PrivateKey clientPK, BigInteger tc, SecureRandom secureRandom, Signature signature)
            throws InvalidKeyException, SignatureException {
        signature.initSign(clientPK, secureRandom);
        signature.update(tc.toByteArray());
        return signature.sign();
    }

    static boolean isSignatureVerify(BigInteger tPublicKey, Certificate certificate, Signature signature, byte[] digitalSignature)
            throws InvalidKeyException, SignatureException {
        signature.initVerify(certificate.getPublicKey());
        signature.update(tPublicKey.toByteArray());
        return signature.verify(digitalSignature);
    }

    static Mac getMac(byte[] bytes) throws NoSuchAlgorithmException, InvalidKeyException {
        String HMAC256 = "HmacSHA256";
        SecretKeySpec secretKeySpec = new SecretKeySpec(bytes, HMAC256);
        Mac mac = Mac.getInstance(HMAC256);
        mac.init(secretKeySpec);
        return mac;
    }

    static byte[] hkdfExpand(byte[] input, byte[] tag) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = new byte[tag.length+1];

        for (int i = 0; i < tag.length; i++) {
            data[i] = tag[i];
        }

        data[tag.length] = 1;
        Mac mac = getMac(input);

        return Arrays.copyOfRange(mac.doFinal(data), 0, 16);
    }

    static void makeSecretKeys(byte[] clientNonce, byte[] sharedSecretFromDiffieHellman)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = getMac(sharedSecretFromDiffieHellman);
        byte[] prk = mac.doFinal(clientNonce);

        serverEncrypt = hkdfExpand(prk, ("server encrypt").getBytes());
        clientEncrypt = hkdfExpand(serverEncrypt, ("client encrypt").getBytes());
        serverMAC = hkdfExpand(clientEncrypt, ("server MAC").getBytes());
        clientMAC = hkdfExpand(serverMAC, ("client MAC").getBytes());
        serverIV = hkdfExpand(clientMAC, ("server IV").getBytes());
        clientIV = hkdfExpand(serverIV, ("client IV").getBytes());

        serverEncryptKey = new SecretKeySpec(serverEncrypt, "AES");
        clientEncryptKey = new SecretKeySpec(clientEncrypt, "AES");
        serverHMACKey = new SecretKeySpec(serverMAC, "SHA256");
        clientHMACKey = new SecretKeySpec(clientMAC, "SHA256");
        serverIVSpec = new IvParameterSpec(serverIV);
        clientIVSpec = new IvParameterSpec(clientIV);
    }
}
