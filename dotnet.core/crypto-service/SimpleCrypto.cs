using System;
using System.IdentityModel.Tokens.Jwt;
using crypto.symmetric;
using crypto_service;
using Microsoft.IdentityModel.Tokens;

namespace com.opusmagus.encryption {    
    public enum AlgorithmEnum { RSA256 }

    public class SimpleCrypto {
        private IJWTService JWTService {get;set;}
        private AlgorithmEnum Algorithm {get;set;}
        public String Issuer {get;set;}
        public DateTime ExpirationDate { get; set; }
        private SymmetricCryptoKey symCryptoKey;

        public SimpleCrypto(string symmetricPW, string salt) {
            JWTService = new RSAJWTService();
            Algorithm = AlgorithmEnum.RSA256;
            Issuer = "opusmagus.com";
            ExpirationDate = new DateTime (1970, 1, 1);
            symCryptoKey = SymmetricCryptoService.CreateSymmetricKey(symmetricPW, salt);
        }
        
        public string GenerateJWT(string writersPrivateKeyContents, string readersPublicKeyContents, string data) {            
            var jwt = JWTService.GenerateJWTFromRSA(ToJWTPayload(data, readersPublicKeyContents), writersPrivateKeyContents, ToString(Algorithm));
            var serializedJWT = new JwtSecurityTokenHandler().WriteToken(jwt);
            return serializedJWT;
        }

        private JwtPayload ToJWTPayload(string data, string readersPublicKeyContents)
        {
            var payload = new JwtPayload { 
                { "iss", Issuer },
                { "encrypted_key_base64", JWTService.Encrypt(symCryptoKey.KeyBase64, readersPublicKeyContents) }, // Receivers public key
                { "encrypted_iv_base64", JWTService.Encrypt(symCryptoKey.IVBase64, readersPublicKeyContents) }, // Receivers public key
                { "sym_encrypted_data", SymmetricCryptoService.Encrypt(data, symCryptoKey.Key, symCryptoKey.IV) }, // These data can be large
                { "exp", (Int32) (DateTime.UtcNow.AddHours(1).Subtract(ExpirationDate)).TotalSeconds }, // Expiration
                { "iat", (Int32) (DateTime.UtcNow.Subtract(ExpirationDate)).TotalSeconds } // Issued At
            };
            return payload;
        }

        private TokenValidationParameters ToTokenValidationParameters() {
            
            var validationParameters = new TokenValidationParameters()
            {
                    //IssuerSigningToken // Not needed
                    //SecurityKey: creds // Not needed
                    //IssuerSigningKey // This is set internally
                    //ValidAudience = "yourdomain.com" // Only used if set to true or default below
                    ValidIssuer = Issuer,
                    ValidateLifetime = true,
                    ValidateAudience = false,
                    ValidateIssuer = true,
                    ValidateIssuerSigningKey = true
            };
            return validationParameters;
        }

        private string ToString(AlgorithmEnum algorithm) {
            switch(algorithm) {
                case AlgorithmEnum.RSA256: return "RS256";
                default: return "RS256";
            }
        }
    }
}