using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace com.opusmagus.encryption {    
    public class RSAJWTService : IJWTService {

        public JwtSecurityToken ReadJWTRSA(string serializedJWT, string publicRSAKeyContents, string algorithm, TokenValidationParameters validationParameters) {
            var securityHandler = new JwtSecurityTokenHandler();
            var rsa = RSA.Create ();
            Nullable<RSAParameters> rsaParameters = new PEMCryptoService().GetRSAProviderFromRSAKeyContents(publicRSAKeyContents);
            if (rsaParameters != null) {
                rsa.ImportParameters (rsaParameters.Value);

                var securityKey = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsaParameters.Value);
                var credentials = new Microsoft.IdentityModel.Tokens.SigningCredentials (securityKey, algorithm);
                validationParameters.IssuerSigningKey = credentials.Key;
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

        public bool ValidateJWTRSA(string serializedJWT, string publicRSAKeyContents, string algorithm, TokenValidationParameters validationParameters)
        {
            var securityHandler = new JwtSecurityTokenHandler();
            var rsa = RSA.Create();
            Nullable<RSAParameters> rsaParameters = new PEMCryptoService().GetRSAProviderFromRSAKeyContents(publicRSAKeyContents);
            if (rsaParameters != null) {
                rsa.ImportParameters (rsaParameters.Value);

                var securityKey = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsaParameters.Value);
                var credentials = new Microsoft.IdentityModel.Tokens.SigningCredentials (securityKey, algorithm);
                validationParameters.IssuerSigningKey = credentials.Key;
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

        public JwtSecurityToken GenerateJWTFromRSA(JwtPayload payload, string privateRSAKeyContents, string algorithm) {
            var rsa = RSA.Create ();
            Nullable<RSAParameters> rsaParameters = new PEMCryptoService().GetRSAProviderFromRSAKeyContents(privateRSAKeyContents);
            if (rsaParameters != null) {
                rsa.ImportParameters (rsaParameters.Value);

                var securityKey = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsaParameters.Value);
                var credentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(securityKey, algorithm);
                var JWTHeader = new JwtHeader (credentials);                
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

        public string Encrypt(string message, string publicRSAKeyContents) {
            byte[] encryptedMessageBytes = null;
            using (var rsa = RSA.Create ()) {
                Nullable<RSAParameters> rsaParameters = new PEMCryptoService().GetRSAProviderFromRSAKeyContents(publicRSAKeyContents);
                if (rsaParameters != null) {
                    rsa.ImportParameters (rsaParameters.Value);
                    encryptedMessageBytes = rsa.Encrypt(Encoding.UTF8.GetBytes(message), RSAEncryptionPadding.Pkcs1);
                    //encryptedMessageBytes = rsa.Encrypt(Encoding.UTF8.GetBytes(message), RSAEncryptionPadding.OaepSHA256);
                    return Convert.ToBase64String(encryptedMessageBytes);
                }
            }
            return null;
        }         

        public string Decrypt(string encryptedMessageBase64, string privateRSAKeyCotents) {
            using (var rsa = RSA.Create ()) {
                Nullable<RSAParameters> rsaParameters = new PEMCryptoService().GetRSAProviderFromRSAKeyContents(privateRSAKeyCotents);
                if (rsaParameters != null) {
                    rsa.ImportParameters (rsaParameters.Value);
                    var encryptedMessageBytes = Convert.FromBase64String(encryptedMessageBase64);
                    //var decrypted = rsa.Decrypt (encryptedMessageBytes, RSAEncryptionPadding.OaepSHA256);
                    var decrypted = rsa.Decrypt (encryptedMessageBytes, RSAEncryptionPadding.Pkcs1);
                    return Encoding.UTF8.GetString(decrypted);
                }
            }
            return null;
        }

        public string GenerateHexHash(string data, HashAlgorithmEnum algorithm)
        {
            if(algorithm == HashAlgorithmEnum.SHA512) {
                using (SHA512 sha = new SHA512Managed())
                {
                    var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(data));
                    string hexHash = BitConverter.ToString(hash).Replace("-", string.Empty);
                    return hexHash;
                }
            }
            throw new Exception("Unsupported hashing algorithm!");
        }        

        public string GenerateBase64Hash(string data, HashAlgorithmEnum algorithm)
        {
            if(algorithm == HashAlgorithmEnum.SHA512) {
                using (SHA512 sha = new SHA512Managed())
                {
                    var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(data));
                    return Convert.ToBase64String(hash);
                }
            }
            throw new Exception("Unsupported hashing algorithm!");
        }        

        public bool ValidateBase64Hash(string data, string base64Hash, HashAlgorithmEnum algorithm)
        {
            if(algorithm == HashAlgorithmEnum.SHA512) {
                using (SHA512 sha = new SHA512Managed())
                {
                    var newHash = sha.ComputeHash(Encoding.UTF8.GetBytes(data));
                    return base64Hash.Equals(Convert.ToBase64String(newHash));
                }
            }
            throw new Exception("Unsupported hashing algorithm!");
        }

        public bool ValidateHexHash(string data, string hexHash, HashAlgorithmEnum algorithm)
        {
            if(algorithm == HashAlgorithmEnum.SHA512) {
                using (SHA512 sha = new SHA512Managed())
                {
                    var newHash = sha.ComputeHash(Encoding.UTF8.GetBytes(data));
                    string newHexHash = BitConverter.ToString(newHash).Replace("-", string.Empty);
                    Console.WriteLine($"newHexHash={newHexHash}");
                    return hexHash.ToUpper().Equals(newHexHash.ToUpper());
                }
            }
            throw new Exception("Unsupported hashing algorithm!");
        }        
    }
}