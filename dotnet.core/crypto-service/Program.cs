using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using crypto.symmetric;
using crypto_service;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace com.opusmagus.encryption
{
    class Program
    {
        // Public keys are known by both party "A" and party "B"
        public static string RSAPublicKeySet1Contents { get; private set; }
        public static string RSAPublicKeySet2Contents { get; private set; }
        public static string RSAPublicKeySet1BadContents { get; private set; }
        public static readonly string LocalFileStorePath = @"C:\data\github\crypto-service\local";

        static void Main (string[] args) {
            Console.WriteLine("Started...");
            SimulateWebAPI();
            //SimpleTest();
            Console.WriteLine("Ended!");
        }

        private static void SimpleTest()
        {
            var lukesPrivateKeyContents = File.ReadAllText(@".\local\rsa-prv-key-set1.key");
            var lukesPublicKeyContents = File.ReadAllText(@".\local\rsa-pub-key-set1.key");
            var yodasPrivateKeyContents = File.ReadAllText(@".\local\rsa-prv-key-set2.key");
            var yodasPublicKeyContents = File.ReadAllText(@".\local\rsa-pub-key-set2.key");
            var simpleCrypto = new SimpleCrypto("my-awesome-pw", "my-tasty-salt");
            var jwt = simpleCrypto.GenerateJWT(lukesPrivateKeyContents, yodasPublicKeyContents, "my s3cr3t data");
            Console.WriteLine(jwt);
        }

        private static void SimulateWebAPI()
        {
            Console.WriteLine("Genereate your keys e.g. via this online tool for testing http://travistidwell.com/jsencrypt/demo/, via 'keystore explorer' or using openssl!");
            Console.WriteLine("Verify your tokens and signature via https://jwt.io/");

            RSAPublicKeySet1Contents = File.ReadAllText($@"{LocalFileStorePath}\keys\rsa-pub-key-set1.key");
            RSAPublicKeySet2Contents = File.ReadAllText($@"{LocalFileStorePath}\keys\rsa-pub-key-set2.key");
            RSAPublicKeySet1BadContents = File.ReadAllText($@"{LocalFileStorePath}\keys\rsa-pub-key-set1-bad.key");
            Directory.CreateDirectory($@"{LocalFileStorePath}\requests");
            Directory.CreateDirectory($@"{LocalFileStorePath}\replies");
            
            SimulateSender();            
            //SimulateReceiver();
            //SimulateReceiverWithBadKey(simpleMessage);

            Console.WriteLine ("Ended!");
        }

        private static void SimulateSender()
        {
            IJWTService jwtService = new RSAJWTService();
            var shortSecretData = "This is my string content, that I want to encrypt with the receivers public key, THE END.";
            var longSecretData = File.ReadAllText(".\\resources\\large-text.txt");

            var symCryptoKey = SymmetricCryptoService.CreateSymmetricKey("my-awesome-pw", "my-tasty-salt");
            var encryptedData = SymmetricCryptoService.Encrypt(longSecretData, symCryptoKey.Key, symCryptoKey.IV);
            Console.WriteLine($"encryptedData:{encryptedData}");
            var decryptedData = SymmetricCryptoService.Decrypt(encryptedData, symCryptoKey.Key, symCryptoKey.IV);
            Console.WriteLine($"decryptedData:{decryptedData}");

            // This key is only known by one party "A"
            var rsaPrivateKeySet1Contents = File.ReadAllText($@"{LocalFileStorePath}\keys\rsa-prv-key-set1.key");
            var contentHashBase64 = jwtService.GenerateBase64Hash(longSecretData, HashAlgorithmEnum.SHA512);
            var payload = new JwtPayload { 
                { "iss", "commentor.dk" },
                { "encrypted_key_base64", jwtService.Encrypt(symCryptoKey.KeyBase64, RSAPublicKeySet2Contents) }, // Receivers public key
                { "encrypted_iv_base64", jwtService.Encrypt(symCryptoKey.IVBase64, RSAPublicKeySet2Contents) }, // Receivers public key
                { "content_hash_base64", contentHashBase64 },
                { "content_hash_algorithm", HashAlgorithmEnum.SHA512.ToString() },
                { "exp", (Int32) (DateTime.UtcNow.AddHours (1).Subtract (new DateTime (1970, 1, 1))).TotalSeconds }, 
                { "iat", (Int32) (DateTime.UtcNow.Subtract (new DateTime (1970, 1, 1))).TotalSeconds }
            };
            // Creating signed JWT
            var jwt = jwtService.GenerateJWTFromRSA(payload, rsaPrivateKeySet1Contents, "RS256"); // Senders private  key
            var serializedJWT = new JwtSecurityTokenHandler().WriteToken(jwt);
            Console.WriteLine($"serializedJWT:{serializedJWT}");            
            var simpleMessage = new SimpleMessage{ AuthorizationHeader = serializedJWT, BodyContents =  SymmetricCryptoService.Encrypt(longSecretData, symCryptoKey.Key, symCryptoKey.IV) };
            SendRequest(simpleMessage);
        }

        private static void SimulateReceiver()
        {
            var simpleMessage = GetRequest();
            IJWTService jwtService = new RSAJWTService();
            // This key is only known by one party "B"
            var rsaPrivateKeySet2Contents = File.ReadAllText($@"{LocalFileStorePath}\keys\rsa-prv-key-set2.key");
            // Checking if JWT signature is valid
            var validationParameters = BuildValidationParameters();
            var receivedJWT = simpleMessage.AuthorizationHeader;
            var receivedContent = simpleMessage.BodyContents;
            var jwtIsValid = jwtService.ValidateJWTRSA(receivedJWT, RSAPublicKeySet1Contents, "RS256", validationParameters); // Senders public key            
            Console.WriteLine($"JWT is valid:{jwtIsValid}");
            
            // Decoding if sinature is valid
            var jwtReread = jwtService.ReadJWTRSA(receivedJWT, RSAPublicKeySet1Contents,"RS256", validationParameters); // Senders public key
            Console.WriteLine($"serializedJWTReread:{jwtReread}");
            var contentHashBase64 = jwtReread.Payload.Claims.Where(c => c.Type == "content_hash_base64" ).Single().Value; // Assuming that it always has data
            var contentHashAlgorithm = jwtReread.Payload.Claims.Where(c => c.Type == "content_hash_algorithm" ).Single().Value; // Assuming that it always has data
            var encrypteddKeyBase64 = jwtReread.Payload.Claims.Where(c => c.Type == "encrypted_key_bas64" ).Single().Value; // Assuming that it always has data
            var encrypteddIVBase64 = jwtReread.Payload.Claims.Where(c => c.Type == "encrypted_iv_bas64" ).Single().Value; // Assuming that it always has data

            // Note: The private key from set2 should only be held by opposing party, and never exchanged, as with all private keys
            var symKeyBase64 = jwtService.Decrypt(encrypteddKeyBase64, rsaPrivateKeySet2Contents); // Receivers private key
            var symIVBase64 = jwtService.Decrypt(encrypteddIVBase64, rsaPrivateKeySet2Contents); // Receivers private key
            var symKey = Convert.FromBase64String(symKeyBase64);
            var symIV = Convert.FromBase64String(symIVBase64);
            var decryptedContent = SymmetricCryptoService.Decrypt(receivedContent, symKey, symIV);
            Console.WriteLine($"Decrypted data reread:{decryptedContent}");

            // Validate content hash
            var hashAlgorithm = HashAlgorithmEnum.Parse<HashAlgorithmEnum>(contentHashAlgorithm);
            if(!jwtService.ValidateBase64Hash(decryptedContent, contentHashBase64, hashAlgorithm))
                SendErrorReply("The hash has been corrupted!");
            else
                SendOKReply("JWT was valid and hash was intact!");
        }

        private static void SendOKReply(string message)
        {
            File.WriteAllText($@"{LocalFileStorePath}\replies\{Guid.NewGuid()}.ok.json", message, Encoding.UTF8);
        }

        private static void SendErrorReply(string message)
        {
            File.WriteAllText($@"{LocalFileStorePath}\replies\{Guid.NewGuid()}.err.json", message, Encoding.UTF8);
        }

        private static void SendRequest(SimpleMessage simpleMessage)
        {
            var jsonRequest = JsonConvert.SerializeObject(simpleMessage);
            File.WriteAllText($@"{LocalFileStorePath}\requests\{Guid.NewGuid()}.json", jsonRequest, Encoding.UTF8);
        }        

        private static SimpleMessage GetRequest()
        {
            while(true) {
                var nextRequest = Directory.GetFiles($@"{LocalFileStorePath}\requests\").FirstOrDefault();
                if(nextRequest != null) {
                    var jsonRequest = File.ReadAllText(nextRequest);
                    var simpleMessage = JsonConvert.DeserializeObject<SimpleMessage>(jsonRequest);
                    return simpleMessage;
                }
                else
                    Thread.Sleep(1000);
            }
        }

        private static void SimulateReceiverWithBadKey(SimpleMessage simpleMessage)
        {
            IJWTService jwtService = new RSAJWTService();
            // Trying with a bad key
            var jwtRereadBad = jwtService.ReadJWTRSA(simpleMessage.AuthorizationHeader, RSAPublicKeySet1BadContents, "RS256", BuildValidationParameters());
        }        

        private static TokenValidationParameters BuildValidationParameters()
        {
            return new TokenValidationParameters()
            {
                    //IssuerSigningToken // Not needed
                    //SecurityKey: creds // Not needed
                    //IssuerSigningKey // This is set internally
                    //ValidAudience = "yourdomain.com" // Only used if set to true or default below
                    ValidIssuer = "commentor.dk",
                    ValidateLifetime = true,
                    ValidateAudience = false,
                    ValidateIssuer = true,
                    ValidateIssuerSigningKey = true
            };
        }
    }
}
