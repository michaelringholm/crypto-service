import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class SimpleJWTService implements JWTService {

    private static String getKey(String filename) throws IOException {
        // Read key from file
        String strKeyPEM = "";
        BufferedReader br = new BufferedReader(new FileReader(filename));
        String line;
        while ((line = br.readLine()) != null) {
            strKeyPEM += line + "\n";
        }
        br.close();
        return strKeyPEM;
    }

    public RSAPrivateKey getPrivateKeyFromFile(String filename) throws IOException, GeneralSecurityException {
        String privateKeyPEM = getKey(filename);
        return getPrivateKeyFromString(privateKeyPEM);
    }

    public RSAPrivateKey getPrivateKeyFromString(String key) throws IOException, GeneralSecurityException {
        String privateKeyPEM = key;
        privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----\n", "");
        privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");
        byte[] encoded = Base64.decodeBase64(privateKeyPEM);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(keySpec);
        return privKey;
    }


    public RSAPublicKey getPublicKeyFromFile(String filename) throws IOException, GeneralSecurityException {
        String publicKeyPEM = getKey(filename);
        return getPublicKeyFromString(publicKeyPEM);
    }

    public RSAPublicKey getPublicKeyFromString(String key) throws IOException, GeneralSecurityException {
        String publicKeyPEM = key;
        publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----\n", "");
        publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
        byte[] encoded = Base64.decodeBase64(publicKeyPEM);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(encoded));
        return pubKey;
    }

    public String sign(PrivateKey privateKey, String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        Signature sign = Signature.getInstance("SHA1withRSA");
        sign.initSign(privateKey);
        sign.update(message.getBytes("UTF-8"));
        return new String(Base64.encodeBase64(sign.sign()), "UTF-8");
    }


    public boolean verify(PublicKey publicKey, String message, String signature) throws SignatureException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        Signature sign = Signature.getInstance("SHA1withRSA");
        sign.initVerify(publicKey);
        sign.update(message.getBytes("UTF-8"));
        return sign.verify(Base64.decodeBase64(signature));
    }

    public String encryptRSA(String rawText, PublicKey publicKey) throws IOException, GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.encodeBase64String(cipher.doFinal(rawText.getBytes("UTF-8")));
    }

    public String decryptRSA(String cipherText, PrivateKey privateKey) throws IOException, GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA"); // Seems to be defaulting to PCKS1
        //Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        //Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA-256AndMGF1Padding");
        //Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
        //new AlgorithmParameters();
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(Base64.decodeBase64(cipherText)), "UTF-8");
    }

    public String encryptRijndael(String rawText, byte[] secretKey, byte[] iv) throws IOException, GeneralSecurityException {
        //Cipher cipher = Cipher.getInstance("RSA");
        //Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");
        //Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        //You can use ENCRYPT_MODE or DECRYPT_MODE
        //cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secretKey.getBytes("UTF-8"), "AES"), new IvParameterSpec(iv.getBytes("UTF-8")));
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secretKey, "AES"), new IvParameterSpec(iv));
        //byte[] ciphertext = cipher.doFinal(plaintext);   
        //Cipher cipher = Cipher.getInstance("");
        //cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        //return Base64.encodeBase64String(cipher.doFinal(rawText.getBytes("UTF-8")));
        return Base64.encodeBase64String(cipher.doFinal(rawText.getBytes()));
    }

    public String decryptRijndael(byte[] encryptedText, byte[] secretKey, byte[] iv) throws IOException, GeneralSecurityException {
        //Cipher cipher = Cipher.getInstance("RSA");
        //Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        //Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        //Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");        
        //You can use ENCRYPT_MODE or DECRYPT_MODE
        //cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secretKey.getBytes("UTF-8"), "AES"), new IvParameterSpec(iv.getBytes("UTF-8")));
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(secretKey, "AES"), new IvParameterSpec(iv));
        //byte[] ciphertext = cipher.doFinal(plaintext);   
        //Cipher cipher = Cipher.getInstance("");
        //cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        //return Base64.encodeBase64String(cipher.doFinal(rawText.getBytes("UTF-8")));
        return new String(cipher.doFinal(encryptedText));
    }
}