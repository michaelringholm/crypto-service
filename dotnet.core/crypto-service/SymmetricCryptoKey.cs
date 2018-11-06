using System;

namespace crypto.symmetric
{
    public class SymmetricCryptoKey
    {
        public byte[] Key { get; set; }
        public byte[] IV { get; set; }
        public string KeyBase64 { get{ return Convert.ToBase64String(Key); }  }
        public string IVBase64 { get{ return Convert.ToBase64String(IV); }  }
    }
}