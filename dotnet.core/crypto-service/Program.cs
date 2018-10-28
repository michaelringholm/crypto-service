using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace pem_console
{
    class Program
    {
        static void Main (string[] args) {
            Console.WriteLine("Started...");
            Console.WriteLine("Genereate your keys e.g. via this online tool for testing http://travistidwell.com/jsencrypt/demo/");
            Console.WriteLine("Verify your tokens and signature via https://jwt.io/");
            IJWTService jwtService = new RSAJWTService();

            var validationParameters = new TokenValidationParameters()
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
            var payload = new JwtPayload { 
                { "iss", "commentor.dk" },
                { "encrypted_data", jwtService.Encrypt("My secret data...", @".\local\rsa-pub-key-set2.key") },
                { "exp", (Int32) (DateTime.UtcNow.AddHours (1).Subtract (new DateTime (1970, 1, 1))).TotalSeconds }, 
                { "iat", (Int32) (DateTime.UtcNow.Subtract (new DateTime (1970, 1, 1))).TotalSeconds }
            };
            // Creating signed JWT
            var jwt = jwtService.GenerateJWTFromRSA(payload, @".\local\rsa-prv-key-set1.key", "RS256");
            var serializedJWT = new JwtSecurityTokenHandler().WriteToken(jwt);
            Console.WriteLine($"serializedJWT:{serializedJWT}");
            // Checking if JWT signature is valid
            var jwtIsValid = jwtService.ValidateJWTRSA(serializedJWT, @".\local\rsa-pub-key-set1.key", "RS256", validationParameters);
            Console.WriteLine($"JWT is valid:{jwtIsValid}");
            // Decoding if sinature is valid
            var jwtReread = jwtService.ReadJWTRSA(serializedJWT, @".\local\rsa-pub-key-set1.key","RS256", validationParameters);
            Console.WriteLine($"serializedJWTReread:{jwtReread}");
            var encrypteddData = jwtReread.Payload.Claims.Where(c => c.Type == "encrypted_data" ).Single().Value; // Assuming that it always has data
            // Note: The private key from set2 should only be held by opposing party, and never exchanged, as with all private keys
            Console.WriteLine($"Decrypted data reread:{jwtService.Decrypt(encrypteddData, @".\local\rsa-prv-key-set2.key")}"); 
            // Trying with a bad key
            var jwtRereadBad = jwtService.ReadJWTRSA(serializedJWT, @".\local\rsa-pub-key-set1-bad.key", "RS256", validationParameters);

            Console.WriteLine ("Ended!");
        }        
    }
}
