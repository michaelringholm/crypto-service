package commentor.dk;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.io.File;

public abstract class WebSimulator {
    public static void run() {
        System.out.println("Started...");
        String cipherTextBase64 = "rkAcJLd8Lf0MqrWWHMvEzfwjoFVaAqOL1x9t9sK9Qm297ftAMZICep+s7N4CsjG7Q1GsWy7UGlv5QncmiQawOzxvxKqT6OQZGkOEiwJCjGV5Dlckb+nnOhWrSP5fDLXSitfPU9k0I/CUsn6CEgnxatMMPWm3KXPUG49mycMzNCgUdN3HDxtNZ7FU1iFHfqIAzd0aTuJyzihZ7n1d27pTCUmHcZzW4FOzQURHt06Ca0iB2h7JnIiC1KDGW4Px/VfnKKPIAo1unn6xQKphFVtSDhxNxi/CRT2V3qchXdPen0HPb9geo1QWWtf+rsJXXaZdzt1qD4DmAYvGS0+K2P+qVw==";
        RSAPrivateKey privateKey;
        RSAPublicKey publicKey;

        try {
            String absPath = new File(".").getAbsolutePath();
            privateKey = SimpleCrypt.getPrivateKeyFromFile("./local/rsa-prv-key-set1.key");
            publicKey = SimpleCrypt.getPublicKeyFromFile("./local/rsa-pub-key-set1.key");

            String decryptedMessage = SimpleCrypt.decrypt(cipherTextBase64, privateKey);
            String encryptedTextBase64 = SimpleCrypt.encrypt("Fem flade flødeboller", publicKey);
            System.out.println("decryptedMessage = " + decryptedMessage);
            System.out.println("encryptedTextBase64 = " + encryptedTextBase64);

            sign(privateKey, publicKey);
            String jwtToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJnZXRFbXBsb3llZXMiOiJhbGxvd2VkIiwiaXNzIjoiY29tbWVudG9yIn0.E_RX_e9GGXBmw3Zx4YCmt5qaXTpyXCeJwimuegyR4ibUNJBj7NhNzs6sSC4bZdOm6fEhS2hEIgB1ls63pDWKukZgf2-AkcuRVCmLl1j95UOafqnnu78cyLqbONkQzcCtKhTAwrK7B3oCg4eWxQY91vrS9kwVMK-A7vBOITtJYooO97DDAL8Ji_9bximduEy7h1Foct0v_q9lGLvlposfxsNLLyR44Gvslp6yjHFIs6rx80E9rSD71AZr2_4uRVIuZ2EFvZB0wHR6ieBCFAYBJw2x5A901F3dTe6Qj_hTs4ocS3nRL_thgxCpnjBit8sXeFSTZtMGEv0XHdcDqxauuA";

            // corrupt key
            //publicKey = SimpleCrypt.getPublicKey("/home/mrs/Documents/keys/nb_key_pub.pem");
            verify(privateKey, publicKey, jwtToken);
        } catch (Exception e) {        
            e.printStackTrace();
        }
        
        System.out.println("Ended!");
    }

    private static void verify(RSAPrivateKey privateKey, RSAPublicKey publicKey, String jwtToken) {        
        try {
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm).withIssuer("commentor").build(); //Reusable verifier instance
            DecodedJWT jwt = verifier.verify(jwtToken);
            if(jwt != null)
                System.out.println("Signature OK!");
                
            Map<String, Claim> claimsMap = jwt.getClaims();
            for (String key : claimsMap.keySet()) {
                System.out.println(key + " = " + claimsMap.get(key).asString());
            }
        } catch (JWTVerificationException ex){
            ex.printStackTrace();
        }        
    }

    private static void sign(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
        //Algorithm algorithm = Algorithm.RSA256(keyProvider);
        Algorithm algorithmRS = Algorithm.RSA256(publicKey, privateKey);
        //Use the Algorithm to create and verify JWTs.
        String token = JWT.create().withClaim("getEmployees", "allowed").withIssuer("commentor").sign(algorithmRS);
        System.out.println("jwtToken = " + token);
    }
}