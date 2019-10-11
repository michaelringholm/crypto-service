
import java.io.File;
import java.nio.charset.Charset;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

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
        String pemPrivateKey = FileUtils.readFileToString(new File(FilenameUtils.concat(LocalFileStorePath, "keys/rsa-prv-key-set1.pem")), Charset.forName("UTF-8"));
        String pemPublicKey = FileUtils.readFileToString(new File(FilenameUtils.concat(LocalFileStorePath, "keys/rsa-pub-key-set2.pem")), Charset.forName("UTF-8"));
        RSAPrivateKey privateKey = jwtService.getRSAPrivateKey(pemPrivateKey);
        RSAPublicKey publicKey = jwtService.getRSAPublicKey(pemPublicKey);

        String secret = "pyramids are old"; // Must be 16 bytes to make .Net happy
        String salt = "this is salty bz"; // Must be 16 bytes
        String longSecretData = FileUtils.readFileToString(new File(FilenameUtils.concat(LocalFileStorePath, "data/large-text2.txt")), Charset.forName("UTF-8"));
        if(longSecretData != null && longSecretData.length() > 100) System.out.println("longSecretData=" + longSecretData.substring(0,100));
        else System.out.println("longSecretData=" + longSecretData);
        System.out.println("longSecretData.length=" + longSecretData.length());
        String rsaEncryptedSecretBase64 = jwtService.encryptRSA(secret, publicKey);
        String rsaEncryptedSaltBase64 = jwtService.encryptRSA(salt, publicKey);
        String rijndaelEncryptedTextBase64 = jwtService.encryptRijndael(longSecretData, secret.getBytes(), salt.getBytes());
        if(rijndaelEncryptedTextBase64 != null && rijndaelEncryptedTextBase64.length() > 100) System.out.println("rijndaelEncryptedTextBase64 = " + rijndaelEncryptedTextBase64.substring(0,100));
        else System.out.println("rijndaelEncryptedTextBase64 = " + rijndaelEncryptedTextBase64);
        String contentHashBase64 = jwtService.generateBase64Hash(longSecretData, JWTService.HashAlgorithEnum.SHA512);
        System.out.println("contentHashBase64 = " + contentHashBase64);
        System.out.println("rijndaelEncryptedTextBase64HashBase64 = " + jwtService.generateBase64Hash(rijndaelEncryptedTextBase64, JWTService.HashAlgorithEnum.SHA512));
        Algorithm algorithmRS = Algorithm.RSA256(publicKey, privateKey);        
        JWTCreator.Builder jwtBuilder = JWT.create().withIssuer("commentor.dk").withExpiresAt(DateUtils.addHours(new Date(), 1)).withIssuedAt(new Date());
        jwtBuilder.withClaim("encrypted_secret_base64", rsaEncryptedSecretBase64).withClaim("encrypted_salt_base64", rsaEncryptedSaltBase64).withClaim("content_hash_base64", contentHashBase64).withClaim("content_hash_algorithm", "SHA512");
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
        String pemPrivateKey = FileUtils.readFileToString(new File(FilenameUtils.concat(LocalFileStorePath, "keys/rsa-prv-key-set2.pem")), Charset.forName("UTF-8"));
        String pemPublicKey = FileUtils.readFileToString(new File(FilenameUtils.concat(LocalFileStorePath, "keys/rsa-pub-key-set1.pem")), Charset.forName("UTF-8"));
        RSAPrivateKey privateKey = jwtService.getRSAPrivateKey(pemPrivateKey);
        RSAPublicKey publicKey = jwtService.getRSAPublicKey(pemPublicKey);
                
        DecodedJWT jwt = verifyToken(publicKey, simpleMessage.AuthorizationHeader);
        String encryptedSecretBase64 = jwt.getClaim("encrypted_secret_base64").asString();
        String encryptedSaltBase64 = jwt.getClaim("encrypted_salt_base64").asString();
        String contentHashBase64 = jwt.getClaim("content_hash_base64").asString();
        String contentHashAlgorithm = jwt.getClaim("content_hash_algorithm").asString();
        
        String secret = jwtService.decryptRSA(encryptedSecretBase64, privateKey);
        String salt = jwtService.decryptRSA(encryptedSaltBase64, privateKey);
        System.out.println(String.format("secret = %s", secret));
        System.out.println(String.format("salt = %s [%d] bytes long", salt, salt.getBytes().length));
        
        String decryptedMessage = jwtService.decryptRijndael(Base64.decodeBase64(simpleMessage.BodyContents), secret.getBytes(), salt.getBytes());
        if(decryptedMessage != null && decryptedMessage.length() > 100) System.out.println("decryptedMessage=" + decryptedMessage.substring(0, 100));
        else System.out.println("decryptedMessage=" + decryptedMessage);
        System.out.println(String.format("contentHashBase64=%s", contentHashBase64));
        JWTService.HashAlgorithEnum hashAlgorithm = JWTService.HashAlgorithEnum.valueOf(contentHashAlgorithm);
        if(!jwtService.validateBase64Hash(decryptedMessage, contentHashBase64, hashAlgorithm)) {
            System.err.println("The content hash has been corrupted, do not continue to use these data!");
            SendErrorReply("The content hash has been corrupted, do not continue to use these data!");
        }
        else {
            System.out.println("JWT was valid and hash was intact!");
            SendOKReply("JWT was valid and hash was intact!");
        }        
    }  

    private static void SendOKReply(String string) {
    }

    private static void SendErrorReply(String string) {
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
                nextRequest.delete();
                return simpleMessage;
            }
            else {
                System.out.println("No messages found, sleeping for 5 seconds...");
                Thread.sleep(5000);
            }
        }
    }    
}