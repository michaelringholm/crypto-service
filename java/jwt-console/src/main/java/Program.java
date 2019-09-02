
import java.io.File;
import java.nio.charset.Charset;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

public class Program {
    public static final String LocalFileStorePath = "c:\\data\\github\\crypto-service\\local";
    public static final Gson jsonConverter = new Gson();

    public static void main(String[] args) {
        System.out.println("Started...");        
        try {
            //simulateSender();
            simulateReceiver();
            //String jwtToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJnZXRFbXBsb3llZXMiOiJhbGxvd2VkIiwiaXNzIjoiY29tbWVudG9yIn0.E_RX_e9GGXBmw3Zx4YCmt5qaXTpyXCeJwimuegyR4ibUNJBj7NhNzs6sSC4bZdOm6fEhS2hEIgB1ls63pDWKukZgf2-AkcuRVCmLl1j95UOafqnnu78cyLqbONkQzcCtKhTAwrK7B3oCg4eWxQY91vrS9kwVMK-A7vBOITtJYooO97DDAL8Ji_9bximduEy7h1Foct0v_q9lGLvlposfxsNLLyR44Gvslp6yjHFIs6rx80E9rSD71AZr2_4uRVIuZ2EFvZB0wHR6ieBCFAYBJw2x5A901F3dTe6Qj_hTs4ocS3nRL_thgxCpnjBit8sXeFSTZtMGEv0XHdcDqxauuA";

            // corrupt key
            //publicKey = SimpleCrypt.getPublicKey("/home/mrs/Documents/keys/nb_key_pub.pem");            
        } catch (Exception e) {        
            e.printStackTrace();
        }
        
        System.out.println("Ended!");
    }

    private static void simulateSender() throws Exception {
        JWTService jwtService = new SimpleJWTService();
        RSAPrivateKey privateKey = jwtService.getPrivateKeyFromFile(FilenameUtils.concat(LocalFileStorePath, "keys/rsa-prv-key-set1.pem"));
        RSAPublicKey publicKey = jwtService.getPublicKeyFromFile(FilenameUtils.concat(LocalFileStorePath, "keys/rsa-pub-key-set1.pem"));

        String secretKey = "Fem flade flødeboller";
        String iv = "";
        String bigData = "dajsdlkjaskdj";
        String rsaEncryptedSecretBase64 = jwtService.encryptRSA(secretKey, publicKey);
        String rsaEncryptedIVBase64 = jwtService.encryptRSA(iv, publicKey);
        String rijndaelEncryptedTextBase64 = jwtService.encryptRijndael(bigData, secretKey, iv);
        System.out.println("rijndaelEncryptedTextBase64 = " + rijndaelEncryptedTextBase64);
        Algorithm algorithmRS = Algorithm.RSA256(publicKey, privateKey);        
        String jwtToken = JWT.create().withClaim("getEmployees", "allowed").withIssuer("commentor.dk").sign(algorithmRS);        
        System.out.println("jwtToken = " + jwtToken);

        SimpleMessage simpleMessage = new SimpleMessage();
        simpleMessage.AuthorizationHeader = jwtToken;
        simpleMessage.BodyContents = rijndaelEncryptedTextBase64;
        sendRequest(simpleMessage);
    }

    private static void simulateReceiver() throws Exception {
        SimpleMessage simpleMessage = getRequest();
        JWTService jwtService = new SimpleJWTService();
        RSAPrivateKey privateKey = jwtService.getPrivateKeyFromFile(FilenameUtils.concat(LocalFileStorePath, "keys/rsa-prv-key-set2.pem"));
        RSAPublicKey publicKey = jwtService.getPublicKeyFromFile(FilenameUtils.concat(LocalFileStorePath, "keys/rsa-pub-key-set1.pem"));
                
        DecodedJWT jwt = verifyToken(privateKey, publicKey, simpleMessage.AuthorizationHeader);
        String encryptedkeyBase64 = jwt.getClaim("encrypted_key_base64").asString();
        String encryptedIVBase64 = jwt.getClaim("encrypted_iv_base64").asString();
        String contentHashBase64 = jwt.getClaim("content_hash_base64").asString();
        String contentHashAlgorithm = jwt.getClaim("content_hash_algorithm").asString();
        
        String keyBase64 = jwtService.decryptRSA(encryptedkeyBase64, privateKey);
        String ivBase64 = jwtService.decryptRSA(encryptedIVBase64, privateKey);
        System.out.println(String.format("keyBase64:%s", keyBase64));
        System.out.println(String.format("ivBase64:%s", ivBase64));
        //String decryptedMessage = jwtService.decryptRijndael(simpleMessage.BodyContents, privateKey);            
        //System.out.println("decryptedMessage = " + decryptedMessage);
    }  

    private static DecodedJWT verifyToken(RSAPrivateKey privateKey, RSAPublicKey publicKey, String jwtToken) {
        try {
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm).withIssuer("commentor.dk").build(); //Reusable verifier instance
            DecodedJWT jwt = verifier.verify(jwtToken);
            if(jwt != null)
                System.out.println("Signature OK!");
                
            Map<String, Claim> claimsMap = jwt.getClaims();
            for (String key : claimsMap.keySet()) {
                System.out.println(key + " = " + claimsMap.get(key).asString());
            }
            return jwt;
        } catch (JWTVerificationException ex){
            ex.printStackTrace();
            return null;
        }        
    }

    private static void sendRequest(SimpleMessage simpleMessage) throws Exception {
        String jsonRequest = jsonConverter.toJson(simpleMessage);
        String guid = UUID.randomUUID().toString();
        FileUtils.writeStringToFile(new File(String.format("%s%s", LocalFileStorePath, String.format("%s%s%s", LocalFileStorePath, guid, ".json"))), jsonRequest, Charset.forName("UTF-8"));
    }    

    private static SimpleMessage getRequest() throws Exception {
        while(true) {
            String directory = FilenameUtils.concat(LocalFileStorePath, "requests");
            System.out.println(String.format("directory:%s", directory));
            Iterator<File> nextRequests = FileUtils.iterateFiles(new File(directory), new String[]{"json"}, false);
            if(nextRequests != null && nextRequests.hasNext()) {
                File nextRequest = nextRequests.next();
                String jsonRequest = FileUtils.readFileToString(nextRequest, Charset.forName("UTF-8"));
                SimpleMessage simpleMessage = jsonConverter.fromJson(jsonRequest, SimpleMessage.class);
                return simpleMessage;
            }
            else
                Thread.sleep(1000);
        }
    }    
}