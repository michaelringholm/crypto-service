using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using crypto.symmetric;
using crypto_service;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using service_layer;

namespace crypto_service
{
    public static class JWTHelper
    {
        public static String ToJWTBase64(dynamic data, ILogger logger, ISecurityVault securityVault, String issuer, String symPWSecretName, String symSaltSecretName, String senderPrivateKeyName, String receiverPublicKeyName)
        {
            IJWTService jwtService = new RSAJWTService();

            var longSecretData = JsonConvert.SerializeObject(data);
            var symCryptoKey = SymmetricCryptoService.CreateSymmetricKey(securityVault.GetSecret(symPWSecretName), securityVault.GetSecret(symSaltSecretName));
            var encryptedData = SymmetricCryptoService.Encrypt(longSecretData, symCryptoKey.Key, symCryptoKey.IV);
            logger.LogInformation($"encryptedData:{encryptedData}");
            //var decryptedData = SymmetricCryptoService.Decrypt(encryptedData, symCryptoKey.Key, symCryptoKey.IV);            
            //logger.LogInformation($"decryptedData:{decryptedData}");

            var rsaPrivateKeySet1Contents = securityVault.GetSecret(senderPrivateKeyName);
            var rsaPublicKeySet2Contents = securityVault.GetSecret(receiverPublicKeyName);
            var validationParameters = getValidationParameters(issuer);
                        
            var payload = new JwtPayload { 
                { "iss", issuer },
                { "encrypted_key_bas64", jwtService.Encrypt(symCryptoKey.KeyBase64, rsaPublicKeySet2Contents) }, // Receivers public key
                { "encrypted_iv_bas64", jwtService.Encrypt(symCryptoKey.IVBase64, rsaPublicKeySet2Contents) }, // Receivers public key
                { "sym_encrypted_data", SymmetricCryptoService.Encrypt(longSecretData, symCryptoKey.Key, symCryptoKey.IV) }, // These data can be large
                { "exp", (Int32) (DateTime.UtcNow.AddHours (1).Subtract (new DateTime (1970, 1, 1))).TotalSeconds }, 
                { "iat", (Int32) (DateTime.UtcNow.Subtract (new DateTime (1970, 1, 1))).TotalSeconds }
            };
            // Creating signed JWT
            var jwt = jwtService.GenerateJWTFromRSA(payload, rsaPrivateKeySet1Contents, "RS256"); // Senders private  key
            var serializedJWT = new JwtSecurityTokenHandler().WriteToken(jwt);
            logger.LogInformation($"serializedJWT:{serializedJWT}");
            return serializedJWT;
        }

        private static TokenValidationParameters getValidationParameters(string issuer)
        {
            var validationParameters = new TokenValidationParameters()
            {
                    //IssuerSigningToken // Not needed
                    //SecurityKey: creds // Not needed
                    //IssuerSigningKey // This is set internally
                    //ValidAudience = "yourdomain.com" // Only used if set to true or default below
                    ValidIssuer = issuer,
                    ValidateLifetime = true,
                    ValidateAudience = false,
                    ValidateIssuer = true,
                    ValidateIssuerSigningKey = true
            };
            return validationParameters;
        }

        public static String FromJWTBase64(String serializedJWT, ILogger logger, ISecurityVault securityVault, String issuer, String symPWSecretName, String symSaltSecretName, String receiverPrivateKeyName, String senderPublicKeyName)
        {
             IJWTService jwtService = new RSAJWTService();
            var symCryptoKey = SymmetricCryptoService.CreateSymmetricKey(securityVault.GetSecret(symPWSecretName), securityVault.GetSecret(symSaltSecretName));
            var rsaPrivateKeySet2Contents = securityVault.GetSecret(receiverPrivateKeyName);
            var rsaPublicKeySet1Contents = securityVault.GetSecret(senderPublicKeyName);
            var validationParameters = getValidationParameters(issuer);
            
            var jwtIsValid = jwtService.ValidateJWTRSA(serializedJWT, rsaPublicKeySet1Contents, "RS256", validationParameters); // Senders public key
            Console.WriteLine($"JWT is valid:{jwtIsValid}");
            if(!jwtIsValid)
                throw new Exception("Invalid JWT signature");
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
            var decryptedData = SymmetricCryptoService.Decrypt(encrypteddData, symKey, symIV);
            Console.WriteLine($"Decrypted data reread:{decryptedData}");

            return decryptedData;
        }
    }
}