using System;

namespace service_layer
{
    public interface ISecurityVault
    {
        String GetSecret(String secretName);
    }
}
