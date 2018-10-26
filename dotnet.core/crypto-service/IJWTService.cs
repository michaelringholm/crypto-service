using System.IdentityModel.Tokens.Jwt;

namespace pem_console
{
    public interface IJWTService
    {
        JwtSecurityToken GenerateJWTFromRSA(string privateKey);
        bool ValidateJWTRSA(string serializedJWT, string publicKey);
        JwtSecurityToken ReadJWTRSA(string serializedJWT, string publicKey);
    }
}