using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace pem_console {    
    public class RSAJWTService : IJWTService {

        public JwtSecurityToken ReadJWTRSA(string serializedJWT, string publicKey) {
            var securityHandler = new JwtSecurityTokenHandler();
            var rsa = RSA.Create ();
            Nullable<RSAParameters> rsaParameters = new PEMCryptoService().GetRSAProviderFromPemFile(publicKey);
            if (rsaParameters != null) {
                rsa.ImportParameters (rsaParameters.Value);

                var securityKey = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsaParameters.Value);
                var credentials = new Microsoft.IdentityModel.Tokens.SigningCredentials (securityKey, "RS256");

                var validationParameters = new TokenValidationParameters()
                {
                    //IssuerSigningToken = new BinarySecretSecurityToken(_key),
                // SecurityKey: creds,
                    IssuerSigningKey = credentials.Key,
                    //ValidAudience = "yourdomain.com",
                    ValidIssuer = "commentor.dk",
                    ValidateLifetime = true,
                    ValidateAudience = false,
                    ValidateIssuer = true,
                    ValidateIssuerSigningKey = true
                };

                SecurityToken validatedToken;
                try {
                    securityHandler.ValidateToken(serializedJWT, validationParameters, out validatedToken);
                    if(validatedToken == null)
                        throw new Exception("Validation of signature failed! Don't trust these data!");
                    return securityHandler.ReadJwtToken(serializedJWT);
                }
                catch(SecurityTokenInvalidSignatureException) {
                    throw new Exception("Validation of signature failed! Don't trust these data!");
                }
            }
            return null;
            
        }        

        public bool ValidateJWTRSA(string serializedJWT, string publicKey)
        {
            var securityHandler = new JwtSecurityTokenHandler();
            var rsa = RSA.Create ();
            Nullable<RSAParameters> rsaParameters = new PEMCryptoService().GetRSAProviderFromPemFile(publicKey);
            if (rsaParameters != null) {
                rsa.ImportParameters (rsaParameters.Value);

                var securityKey = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsaParameters.Value);
                var credentials = new Microsoft.IdentityModel.Tokens.SigningCredentials (securityKey, "RS256");

                var validationParameters = new TokenValidationParameters()
                {
                    //IssuerSigningToken = new BinarySecretSecurityToken(_key),
                // SecurityKey: creds,
                    IssuerSigningKey = credentials.Key,
                    //ValidAudience = "yourdomain.com",
                    ValidIssuer = "commentor.dk",
                    ValidateLifetime = true,
                    ValidateAudience = false,
                    ValidateIssuer = true,
                    ValidateIssuerSigningKey = true
                };

                SecurityToken validatedToken;
                try {
                    securityHandler.ValidateToken(serializedJWT, validationParameters, out validatedToken);
                }
                catch(SecurityTokenInvalidSignatureException) {
                    return false;
                }
                return validatedToken != null;
            }
            return false;
        }          

        public JwtSecurityToken GenerateJWTFromRSA(string privateKey) {
            var rsa = RSA.Create ();
            Nullable<RSAParameters> rsaParameters = new PEMCryptoService().GetRSAProviderFromPemFile (privateKey);
            if (rsaParameters != null) {
                rsa.ImportParameters (rsaParameters.Value);

                var securityKey = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsaParameters.Value);
                var credentials = new Microsoft.IdentityModel.Tokens.SigningCredentials (securityKey, "RS256");
                var JWTHeader = new JwtHeader (credentials);
                var payload = new JwtPayload { 
                    { "iss", "commentor.dk" }, 
                    { "exp", (Int32) (DateTime.UtcNow.AddHours (1).Subtract (new DateTime (1970, 1, 1))).TotalSeconds }, 
                    { "iat", (Int32) (DateTime.UtcNow.Subtract (new DateTime (1970, 1, 1))).TotalSeconds }
                };
                var token = new JwtSecurityToken (JWTHeader, payload);
                return token;
            }
            return null;
        }   

        private static X509Certificate2 GetByThumbprint(string thumbprint)
        {
            var localStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            localStore.Open(OpenFlags.ReadOnly);
            return localStore.Certificates//.Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.DigitalSignature, false)
                .Find(X509FindType.FindByThumbprint, thumbprint, false)
                .OfType<X509Certificate2>().First();
        }                  

        private static JwtSecurityToken GenerateJWTFromX509 () {
            var securityKey = new Microsoft.IdentityModel.Tokens.X509SecurityKey (GetByThumbprint ("YOUR-CERT-THUMBPRINT-HERE"));
            var credentials = new Microsoft.IdentityModel.Tokens.SigningCredentials (securityKey, "RS256");
            var JWTHeader = new JwtHeader (credentials);
            var payload = new JwtPayload { 
                { "iss", "Issuer-here" }, 
                { "exp", (Int32) (DateTime.UtcNow.AddHours (1).Subtract (new DateTime (1970, 1, 1))).TotalSeconds }, 
                { "iat", (Int32) (DateTime.UtcNow.Subtract (new DateTime (1970, 1, 1))).TotalSeconds }
            };
            var token = new JwtSecurityToken (JWTHeader, payload);
            return token;
        }

        public static void EncryptDecrypt(string publicKey, string privateKey) {
            byte[] encryptedMessageBytes = null;

            using (var rsa = RSA.Create ()) {
                Nullable<RSAParameters> rsaParameters = new PEMCryptoService().GetRSAProviderFromPemFile (publicKey);
                if (rsaParameters != null) {
                    rsa.ImportParameters (rsaParameters.Value);
                    encryptedMessageBytes = rsa.Encrypt (Encoding.UTF8.GetBytes ("Hello from dotNet.core"), RSAEncryptionPadding.Pkcs1);
                    Console.WriteLine ($"Encrypted={Encoding.UTF8.GetString(encryptedMessageBytes)}");
                }
            }

            using (var rsa = RSA.Create ()) {
                Nullable<RSAParameters> rsaParameters = new PEMCryptoService().GetRSAProviderFromPemFile (privateKey);
                if (rsaParameters != null) {
                    rsa.ImportParameters (rsaParameters.Value);
                    var decrypted = rsa.Decrypt (encryptedMessageBytes, RSAEncryptionPadding.Pkcs1);
                    Console.WriteLine ($"Decrypted={Encoding.UTF8.GetString(decrypted)}");
                }
            }
        }         
    }
}