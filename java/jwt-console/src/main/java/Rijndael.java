import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

public class Rijndael {
	public static  String encrypt(String plainText, byte[] key) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
		int blockSize = cipher.getBlockSize();
		byte[] dataBytes = plainText.getBytes();
		int plaintTextLength = dataBytes.length;
		if (plaintTextLength % blockSize != 0)
			plaintTextLength = plaintTextLength + (blockSize - (plaintTextLength % blockSize));
		byte[] plainTextByte = new byte[plaintTextLength];
		System.arraycopy(dataBytes, 0, plainTextByte, 0, dataBytes.length);
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
		return Base64.encodeBase64String(cipher.doFinal(plainTextByte)) + String.format("%06d", plainText.length());
	}

	public static  String decrypt(String cipherText, byte[] key) throws Exception {
		int plainTextLength = Integer.parseInt(cipherText.substring(cipherText.length() - 6));
		cipherText = cipherText.substring(0, cipherText.length() - 6);
		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
		return new String(cipher.doFinal(Base64.decodeBase64(cipherText.getBytes()))).substring(0, plainTextLength);
	}
}