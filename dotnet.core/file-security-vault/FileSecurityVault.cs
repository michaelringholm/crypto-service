using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using service_layer;

namespace file_security_vault
{
    public class FileSecurityVault : ISecurityVault
    {
        private IDictionary<String, String> secrets = new Dictionary<String,String>();
        public FileSecurityVault(ILogger logger, IConfiguration config) {
            var securityVaultPath = config?.GetSection("SecurityVaultPath")?.Value;
            if(securityVaultPath == null)
                throw new Exception($"Section [SecurityVaultPath] is missing from app settings");
            logger.LogInformation($"securityVaultPath={securityVaultPath}");
            Directory.SetCurrentDirectory(securityVaultPath);
            logger.LogInformation($"CurrentDir={Directory.GetCurrentDirectory()}");
        }
        public string GetSecret(string secretName)
        {
            if(!secrets.ContainsKey(secretName)) {
                if(!File.Exists(secretName))
                    throw new Exception($"Secrets file missing for secret with name {secretName}");
                secrets.Add(secretName, File.ReadAllText(secretName));
            }
            return secrets[secretName];
        }
    }
}
