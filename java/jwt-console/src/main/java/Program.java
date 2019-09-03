
import java.io.File;
import java.nio.charset.Charset;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

import javax.lang.model.util.SimpleElementVisitor6;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.time.DateUtils;

public class Program {
    public static final String LocalFileStorePath = "c:\\data\\github\\crypto-service\\local";
    public static final Gson jsonConverter = new Gson();

    public static void main(String[] args) {
        System.out.println("Started...");        
        try {
            System.out.println("Welcome to the Web API Simulator, what would you like to do?");
            System.out.println("1. Simulate Sender");
            System.out.println("2. Simulate Receiver");
            System.out.println("3. Exit");
            int keyRead = System.in.read();
            switch(keyRead) {
                case '1' : simulateSender(); break;
                case '2' : simulateReceiver(); break;
                case '3' : System.out.println("Exiting!"); break;
                default : System.err.println("Unknown choice!"); break;
            }            

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
        RSAPublicKey publicKey = jwtService.getPublicKeyFromFile(FilenameUtils.concat(LocalFileStorePath, "keys/rsa-pub-key-set2.pem"));

        String secretKey = "pyramids are old"; // Must be 16 bytes to make .Net happy
        String iv = "this is salty bz"; // Must be 16 bytes
        String longSecretData = FileUtils.readFileToString(new File(FilenameUtils.concat(LocalFileStorePath, "data/large-text2.txt")), Charset.forName("UTF-8"));
        System.out.println("longSecretData = " + longSecretData);
        String rsaEncryptedSecretBase64 = jwtService.encryptRSA(secretKey, publicKey);
        String rsaEncryptedIVBase64 = jwtService.encryptRSA(iv, publicKey);
        String rijndaelEncryptedTextBase64 = jwtService.encryptRijndael(longSecretData, secretKey.getBytes(), iv.getBytes());
        System.out.println("rijndaelEncryptedTextBase64 = " + rijndaelEncryptedTextBase64);
        String contentHashBase64 = jwtService.generateBase64Hash(longSecretData);
        System.out.println("contentHashBase64 = " + contentHashBase64);
        Algorithm algorithmRS = Algorithm.RSA256(publicKey, privateKey);        
        JWTCreator.Builder jwtBuilder = JWT.create().withIssuer("commentor.dk").withExpiresAt(DateUtils.addHours(new Date(), 1)).withIssuedAt(new Date());
        jwtBuilder.withClaim("encrypted_key_base64", rsaEncryptedSecretBase64).withClaim("encrypted_iv_base64", rsaEncryptedIVBase64).withClaim("content_hash_base64", contentHashBase64).withClaim("content_hash_algorithm", "SHA512");
        String jwtToken = jwtBuilder.sign(algorithmRS);
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
                
        DecodedJWT jwt = verifyToken(publicKey, simpleMessage.AuthorizationHeader);
        String encryptedkeyBase64 = jwt.getClaim("encrypted_key_base64").asString();
        String encryptedIVBase64 = jwt.getClaim("encrypted_iv_base64").asString();
        String contentHashBase64 = jwt.getClaim("content_hash_base64").asString();
        String contentHashAlgorithm = jwt.getClaim("content_hash_algorithm").asString();
        
        String secretKey = jwtService.decryptRSA(encryptedkeyBase64, privateKey);
        String iv = jwtService.decryptRSA(encryptedIVBase64, privateKey);
        System.out.println(String.format("secretKey = %s", secretKey));
        System.out.println(String.format("ivBase64 = %s [%d] bytes long", iv, iv.getBytes().length));
        
        if(simpleMessage.BodyContents != null && simpleMessage.BodyContents.length() > 100)
            System.out.println(String.format("simpleMessage.BodyContents:%s", simpleMessage.BodyContents.substring(0, 100)));
        else
            System.out.println(String.format("simpleMessage.BodyContents:%s", simpleMessage.BodyContents));
        String decryptedMessage = jwtService.decryptRijndael(Base64.decodeBase64(simpleMessage.BodyContents), secretKey.getBytes(), iv.getBytes());
        System.out.println("decryptedMessage = " + decryptedMessage);
    }  

    private static DecodedJWT verifyToken(RSAPublicKey publicKey, String jwtToken) {
        try {
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm).build(); //.withIssuer("commentor.dk").build(); //Reusable verifier instance
            DecodedJWT jwt = verifier.verify(jwtToken);
            if(jwt != null) System.out.println("JWS Signature OK!");
            System.out.println("Listing JWT payload...");                
            Map<String, Claim> claimsMap = jwt.getClaims();
            for (String key : claimsMap.keySet())                
                System.out.println(key + " = " + claimsMap.get(key).asString());
            System.out.println("exp="+jwt.getExpiresAt());
            System.out.println("iat="+jwt.getIssuedAt());
            return jwt;
        } catch (JWTVerificationException ex){
            ex.printStackTrace();
            return null;
        }        
    }

    private static void sendRequest(SimpleMessage simpleMessage) throws Exception {
        String jsonRequest = jsonConverter.toJson(simpleMessage);
        String guid = UUID.randomUUID().toString();
        FileUtils.writeStringToFile(new File(FilenameUtils.concat(LocalFileStorePath, String.format("requests/%s%s", guid, ".json"))), jsonRequest, Charset.forName("UTF-8"));
    }    

    private static SimpleMessage getRequest() throws Exception {
        while(true) {
            String directory = FilenameUtils.concat(LocalFileStorePath, "requests");
            Iterator<File> nextRequests = FileUtils.iterateFiles(new File(directory), new String[]{"json"}, false);
            if(nextRequests != null && nextRequests.hasNext()) {
                File nextRequest = nextRequests.next();
                String jsonRequest = FileUtils.readFileToString(nextRequest, Charset.forName("UTF-8"));
                SimpleMessage simpleMessage = jsonConverter.fromJson(jsonRequest, SimpleMessage.class);
                return simpleMessage;
            }
            else {
                System.out.println("No messages found, sleeping for 5 seconds...");
                Thread.sleep(5000);
            }
        }
    }    
}