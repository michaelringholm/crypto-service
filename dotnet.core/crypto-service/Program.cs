using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using crypto.symmetric;
using Microsoft.IdentityModel.Tokens;

namespace crypto_service
{
    class Program
    {
        static void Main (string[] args) {
            Console.WriteLine("Started...");
            Console.WriteLine("Genereate your keys e.g. via this online tool for testing http://travistidwell.com/jsencrypt/demo/");
            Console.WriteLine("Verify your tokens and signature via https://jwt.io/");
            IJWTService jwtService = new RSAJWTService();

            var shortSecretData = "This is my string content, that I want to encrypt with the receivers public key, THE END.";
            var longSecretData = File.ReadAllText(".\\resources\\large-text.txt");

            var symCryptoKey = SymmetricCryptoService.CreateSymmetricKey("my-awesome-pw", "my-tasty-salt");
            var encryptedData = SymmetricCryptoService.Encrypt(longSecretData, symCryptoKey.Key, symCryptoKey.IV);
            Console.WriteLine($"encryptedData:{encryptedData}");
            var decryptedData = SymmetricCryptoService.Decrypt(encryptedData, symCryptoKey.Key, symCryptoKey.IV);            
            Console.WriteLine($"decryptedData:{decryptedData}");

            var rsaPrivateKeySet1Contents = File.ReadAllText(@".\local\rsa-prv-key-set1.key");
            var rsaPublicKeySet1Contents = File.ReadAllText(@".\local\rsa-pub-key-set1.key");
            var rsaPrivateKeySet2Contents = File.ReadAllText(@".\local\rsa-prv-key-set2.key");
            var rsaPublicKeySet2Contents = File.ReadAllText(@".\local\rsa-pub-key-set2.key");
            var rsaPublicKeySet1BadContents = File.ReadAllText(@".\local\rsa-pub-key-set1-bad.key");

            var validationParameters = new TokenValidationParameters()
            {
                    //IssuerSigningToken // Not needed
                    //SecurityKey: creds // Not needed
                    //IssuerSigningKey // This is set internally
                    //ValidAudience = "yourdomain.com" // Only used if set to true or default below
                    ValidIssuer = "opusmagus.com",
                    ValidateLifetime = true,
                    ValidateAudience = false,
                    ValidateIssuer = true,
                    ValidateIssuerSigningKey = true
            };
                        
            var payload = new JwtPayload { 
                { "iss", "opusmagus.com" },
                { "encrypted_key_bas64", jwtService.Encrypt(symCryptoKey.KeyBase64, rsaPublicKeySet2Contents) }, // Receivers public key
                { "encrypted_iv_bas64", jwtService.Encrypt(symCryptoKey.IVBase64, rsaPublicKeySet2Contents) }, // Receivers public key
                { "sym_encrypted_data", SymmetricCryptoService.Encrypt(longSecretData, symCryptoKey.Key, symCryptoKey.IV) }, // These data can be large
                { "exp", (Int32) (DateTime.UtcNow.AddHours (1).Subtract (new DateTime (1970, 1, 1))).TotalSeconds }, 
                { "iat", (Int32) (DateTime.UtcNow.Subtract (new DateTime (1970, 1, 1))).TotalSeconds }
            };
            // Creating signed JWT
            var jwt = jwtService.GenerateJWTFromRSA(payload, rsaPrivateKeySet1Contents, "RS256"); // Senders private  key
            var serializedJWT = new JwtSecurityTokenHandler().WriteToken(jwt);
            Console.WriteLine($"serializedJWT:{serializedJWT}");
            // Checking if JWT signature is valid
            var jwtIsValid = jwtService.ValidateJWTRSA(serializedJWT, rsaPublicKeySet1Contents, "RS256", validationParameters); // Senders public key
            Console.WriteLine($"JWT is valid:{jwtIsValid}");
            // Decoding if sinature is valid
            var jwtReread = jwtService.ReadJWTRSA(serializedJWT, rsaPublicKeySet1Contents,"RS256", validationParameters); // Senders public key
            Console.WriteLine($"serializedJWTReread:{jwtReread}");
            var encrypteddData = jwtReread.Payload.Claims.Where(c => c.Type == "sym_encrypted_data" ).Single().Value; // Assuming that it always has data
            var encrypteddKeyBase64 = jwtReread.Payload.Claims.Where(c => c.Type == "encrypted_key_bas64" ).Single().Value; // Assuming that it always has data
            var encrypteddIVBase64 = jwtReread.Payload.Claims.Where(c => c.Type == "encrypted_iv_bas64" ).Single().Value; // Assuming that it always has data
            // Note: The private key from set2 should only be held by opposing party, and never exchanged, as with all private keys
            var symKeyBase64 = jwtService.Decrypt(encrypteddKeyBase64, rsaPrivateKeySet2Contents); // Receivers private key
            var symIVBase64 = jwtService.Decrypt(encrypteddIVBase64, rsaPrivateKeySet2Contents); // Receivers private key
            var symKey = Convert.FromBase64String(symKeyBase64);
            var symIV = Convert.FromBase64String(symIVBase64);
            Console.WriteLine($"Decrypted data reread:{SymmetricCryptoService.Decrypt(encrypteddData, symKey, symIV)}"); 
            // Trying with a bad key
            var jwtRereadBad = jwtService.ReadJWTRSA(serializedJWT, rsaPublicKeySet1BadContents, "RS256", validationParameters);

            Console.WriteLine ("Ended!");
        }        
    }
}
