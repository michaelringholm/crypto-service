
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

public class Program {
    //private static String cipherTextBase64 = "rkAcJLd8Lf0MqrWWHMvEzfwjoFVaAqOL1x9t9sK9Qm297ftAMZICep+s7N4CsjG7Q1GsWy7UGlv5QncmiQawOzxvxKqT6OQZGkOEiwJCjGV5Dlckb+nnOhWrSP5fDLXSitfPU9k0I/CUsn6CEgnxatMMPWm3KXPUG49mycMzNCgUdN3HDxtNZ7FU1iFHfqIAzd0aTuJyzihZ7n1d27pTCUmHcZzW4FOzQURHt06Ca0iB2h7JnIiC1KDGW4Px/VfnKKPIAo1unn6xQKphFVtSDhxNxi/CRT2V3qchXdPen0HPb9geo1QWWtf+rsJXXaZdzt1qD4DmAYvGS0+K2P+qVw==";

    public static void main(String[] args) {
        System.out.println("Started...");        
        try {
            SimpleMessage simpleMessage = simulateSender();
            simulateReceiver(simpleMessage);           
            //String jwtToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJnZXRFbXBsb3llZXMiOiJhbGxvd2VkIiwiaXNzIjoiY29tbWVudG9yIn0.E_RX_e9GGXBmw3Zx4YCmt5qaXTpyXCeJwimuegyR4ibUNJBj7NhNzs6sSC4bZdOm6fEhS2hEIgB1ls63pDWKukZgf2-AkcuRVCmLl1j95UOafqnnu78cyLqbONkQzcCtKhTAwrK7B3oCg4eWxQY91vrS9kwVMK-A7vBOITtJYooO97DDAL8Ji_9bximduEy7h1Foct0v_q9lGLvlposfxsNLLyR44Gvslp6yjHFIs6rx80E9rSD71AZr2_4uRVIuZ2EFvZB0wHR6ieBCFAYBJw2x5A901F3dTe6Qj_hTs4ocS3nRL_thgxCpnjBit8sXeFSTZtMGEv0XHdcDqxauuA";

            // corrupt key
            //publicKey = SimpleCrypt.getPublicKey("/home/mrs/Documents/keys/nb_key_pub.pem");            
        } catch (Exception e) {        
            e.printStackTrace();
        }
        
        System.out.println("Ended!");
    }

    private static SimpleMessage simulateSender() throws Exception {
        JWTService jwtService = new SimpleJWTService();
        RSAPrivateKey privateKey = jwtService.getPrivateKeyFromFile("../local/prv-key-set1.pem");
        RSAPublicKey publicKey = jwtService.getPublicKeyFromFile("../local/pub-key-set1.pem");

        String encryptedTextBase64 = jwtService.encryptRSA("Fem flade flødeboller", publicKey);
        System.out.println("encryptedTextBase64 = " + encryptedTextBase64);
        String jwtToken = createJWT(privateKey, publicKey);
        System.out.println("jwtToken = " + jwtToken);
        SimpleMessage simpleMessage = new SimpleMessage();
        simpleMessage.AuthorizationHeader = jwtToken;
        simpleMessage.BodyContents = encryptedTextBase64;
        return simpleMessage;
    }

    private static void simulateReceiver(SimpleMessage simpleMessage) throws Exception {
        JWTService jwtService = new SimpleJWTService();
        RSAPrivateKey privateKey = jwtService.getPrivateKeyFromFile("../local/prv-key-set2.pem");
        RSAPublicKey publicKey = jwtService.getPublicKeyFromFile("../local/pub-key-set1.pem");        
        //String decryptedMessage = SimpleCrypt.decrypt(cipherTextBase64, privateKey);            
        //System.out.println("decryptedMessage = " + decryptedMessage);
        verifyToken(privateKey, publicKey, simpleMessage.AuthorizationHeader);
    }    

    private static void verifyToken(RSAPrivateKey privateKey, RSAPublicKey publicKey, String jwtToken) {
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

    private static String createJWT(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
        //Algorithm algorithm = Algorithm.RSA256(keyProvider);
        Algorithm algorithmRS = Algorithm.RSA256(publicKey, privateKey);
        //Use the Algorithm to create and verify JWTs.
        String jwtToken = JWT.create().withClaim("getEmployees", "allowed").withIssuer("commentor").sign(algorithmRS);        
        return jwtToken;
    }
}