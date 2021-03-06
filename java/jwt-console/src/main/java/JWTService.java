import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public interface JWTService {
    public enum HashAlgorithEnum { SHA512 };
    public RSAPrivateKey getRSAPrivateKey(String pemPrivateKey) throws IOException, GeneralSecurityException;
    public RSAPublicKey getRSAPublicKey(String pemPublicKey) throws IOException, GeneralSecurityException;
    public String sign(PrivateKey privateKey, String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException;
    public boolean verify(PublicKey publicKey, String message, String signature) throws SignatureException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException;
    public String encryptRSA(String rawText, PublicKey publicKey) throws IOException, GeneralSecurityException;
    public String decryptRSA(String cipherText, PrivateKey privateKey) throws IOException, GeneralSecurityException;
    public String encryptRijndael(String rawText, byte[] secretKey, byte[] iv) throws IOException, GeneralSecurityException;
    public String decryptRijndael(byte[] encryptedTextBase64, byte[] secretKey, byte[] iv) throws IOException, GeneralSecurityException;
    public String generateBase64Hash(String text, HashAlgorithEnum hashAlgorithm) throws Exception;
	public boolean validateBase64Hash(String decryptedMessage, String contentHashBase64, HashAlgorithEnum hashAlgorithm);
}