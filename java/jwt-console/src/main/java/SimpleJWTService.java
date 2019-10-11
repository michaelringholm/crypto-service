import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
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
import org.apache.commons.codec.digest.DigestUtils;

public class SimpleJWTService implements JWTService {
    public RSAPrivateKey getRSAPrivateKey(String pemPrivateKey) throws IOException, GeneralSecurityException {
        String privateKeyBase64 = pemPrivateKey;
        privateKeyBase64 = privateKeyBase64.replace("-----BEGIN PRIVATE KEY-----\n", "");
        privateKeyBase64 = privateKeyBase64.replace("-----END PRIVATE KEY-----", "");
        byte[] privateKeyBytes = Base64.decodeBase64(privateKeyBase64);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)kf.generatePrivate(privateKeySpec);
        return rsaPrivateKey;
    }

    public RSAPublicKey getRSAPublicKey(String pemPublicKey) throws IOException, GeneralSecurityException {
        String publicKeyBase64 = pemPublicKey;
        publicKeyBase64 = publicKeyBase64.replace("-----BEGIN PUBLIC KEY-----\n", "");
        publicKeyBase64 = publicKeyBase64.replace("-----END PUBLIC KEY-----", "");
        byte[] publicKeyBytes = Base64.decodeBase64(publicKeyBase64);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKey rsaPublicKey = (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        return rsaPublicKey;
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
        Cipher cipher = Cipher.getInstance("RSA"); // Defaulting to PCKS1, other options are RSA/ECB/OAEPWithSHA-256AndMGF1Padding and more
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(Base64.decodeBase64(cipherText)), "UTF-8");
    }

    public String encryptRijndael(String rawText, byte[] secretKey, byte[] iv) throws IOException, GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secretKey, "AES"), new IvParameterSpec(iv));
        return Base64.encodeBase64String(cipher.doFinal(rawText.getBytes("UTF-8")));
    }

    public String decryptRijndael(byte[] encryptedText, byte[] secretKey, byte[] iv) throws IOException, GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(secretKey, "AES"), new IvParameterSpec(iv));
        return new String(cipher.doFinal(encryptedText), Charset.forName("UTF-8"));
    }
    
    public String generateBase64Hash(String text, HashAlgorithEnum hashAlgorithm) throws Exception {       
        byte[] sha512 = DigestUtils.sha512(text);
        String sha512Base64 = Base64.encodeBase64String(sha512);
        System.out.println("sha512Base64=" + sha512Base64);
        return sha512Base64;
    }

    public String generateHexHash(String text, HashAlgorithEnum hashAlgorithm) throws Exception {
        String sha512Hex = DigestUtils.sha512Hex(text);
        System.out.println("sha512Hex=" + sha512Hex);
        return sha512Hex;
    }    

    public boolean validateBase64Hash(String text, String base64Hash, HashAlgorithEnum hashAlgorithm) {
        byte[] newSha512Hash = DigestUtils.sha512(text);        
        String newSha512HashBase64 = Base64.encodeBase64String(newSha512Hash);
        System.out.println("newSha512HashBase64=" + newSha512HashBase64);
        return newSha512HashBase64.equals(base64Hash);
    }

    public boolean validateHexHash(String text, String hexHash, HashAlgorithEnum hashAlgorithm) {
        String newSha512Hex = DigestUtils.sha512Hex(text);
        System.out.println("newSha512Hex=" + newSha512Hex);
        return newSha512Hex.equals(hexHash);
    }    
}