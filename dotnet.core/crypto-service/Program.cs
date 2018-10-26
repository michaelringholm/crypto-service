using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
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
                { "exp", (Int32) (DateTime.UtcNow.AddHours (1).Subtract (new DateTime (1970, 1, 1))).TotalSeconds }, 
                { "iat", (Int32) (DateTime.UtcNow.Subtract (new DateTime (1970, 1, 1))).TotalSeconds }
            };
            var jwt = jwtService.GenerateJWTFromRSA(payload, @".\local\rsa-prv-key.ppk", "RS256");
            var serializedJWT = new JwtSecurityTokenHandler().WriteToken(jwt);
            Console.WriteLine($"serializedJWT:{serializedJWT}");
            var jwtIsValid = jwtService.ValidateJWTRSA(serializedJWT, @".\local\rsa-pub-key.pub", "RS256", validationParameters);
            Console.WriteLine($"JWT is valid:{jwtIsValid}");
            var jwtReread = jwtService.ReadJWTRSA(serializedJWT, @".\local\rsa-pub-key.pub","RS256", validationParameters);
            Console.WriteLine($"serializedJWTReread:{jwtReread}");
            var jwtRereadBad = jwtService.ReadJWTRSA(serializedJWT, @".\local\rsa-pub-key-bad.pub", "RS256", validationParameters);

            Console.WriteLine ("Ended!");
        }        
    }
}
