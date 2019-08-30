using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace crypto_service
{
    public enum HashAlgorithmEnum{SHA512};
    public interface IJWTService
    {
        JwtSecurityToken GenerateJWTFromRSA(JwtPayload payload, string privateKey, string algorithm);
        bool ValidateJWTRSA(string serializedJWT, string publicKey, string algorithm, TokenValidationParameters validationParameters);
        JwtSecurityToken ReadJWTRSA(string serializedJWT, string publicKey, string algorithm, TokenValidationParameters validationParameters);
        string Encrypt(string message, string publicKey);
        string Decrypt(string encryptedMessage, string privateKey);
        string GenerateBase64Hash(string data, HashAlgorithmEnum algorithm);
        bool ValidateBase64Hash(string data, string base64Hash, HashAlgorithmEnum algorithm);
    }
}