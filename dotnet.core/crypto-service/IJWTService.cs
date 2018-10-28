using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace pem_console
{
    public interface IJWTService
    {
        JwtSecurityToken GenerateJWTFromRSA(JwtPayload payload, string privateKey, string algorithm);
        bool ValidateJWTRSA(string serializedJWT, string publicKey, string algorithm, TokenValidationParameters validationParameters);
        JwtSecurityToken ReadJWTRSA(string serializedJWT, string publicKey, string algorithm, TokenValidationParameters validationParameters);
        string Encrypt(string message, string publicKey);
        string Decrypt(string encryptedMessage, string privateKey);
    }
}