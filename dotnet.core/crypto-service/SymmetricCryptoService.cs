using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace crypto.symmetric
{
    // Key and initialization vector (IV) must be the same bytes in both encrypt and decrypt
    public static class SymmetricCryptoService
    {
        public static SymmetricCryptoKey CreateSymmetricKey(string pw, string salt)
        {
            var rfc2898Key = new Rfc2898DeriveBytes(pw, Encoding.UTF8.GetBytes(salt));
            var key = rfc2898Key.GetBytes(16);
            var iv = rfc2898Key.GetBytes(16);
            return new SymmetricCryptoKey{Key=key, IV=iv};
        }

        public static string Encrypt(string data, byte[] key, byte[] iv, SymmetricAlgorithm symAlgo=null)
        {  
            if(symAlgo==null) symAlgo=new RijndaelManaged();
            MemoryStream memStream = new MemoryStream();
            symAlgo.Padding = PaddingMode.PKCS7;
            CryptoStream cryptoStream = new CryptoStream(memStream, symAlgo.CreateEncryptor(key, iv), CryptoStreamMode.Write);
            StreamWriter streamWriter = new StreamWriter(cryptoStream); 
            streamWriter.Write(data);
            streamWriter.Flush();
            streamWriter.Close();
            cryptoStream.Close();
            var encodedBytes = memStream.ToArray();
            var encodedStringBase64 = Convert.ToBase64String(encodedBytes);
            memStream.Close();

            return encodedStringBase64;
        }

        public static void EncryptFile(FileStream inputStream, FileStream outputStream, byte[] key, byte[] iv, SymmetricAlgorithm symAlgo=null)
        {  
            if(symAlgo==null) symAlgo=new RijndaelManaged();
            symAlgo.Padding = PaddingMode.PKCS7;
            inputStream.Seek(0,0);
            CryptoStream cryptoStream = new CryptoStream(outputStream, symAlgo.CreateEncryptor(key, iv), CryptoStreamMode.Write);
            //StreamWriter streamWriter = new StreamWriter(cryptoStream);
            //StreamReader streamReader = new StreamReader(inputStream);
            //streamWriter.Write(inputStream);
            inputStream.CopyTo(cryptoStream);
            //streamWriter.Flush();
            //streamWriter.Close();
            cryptoStream.Close();
        }

        public static void DecryptFile(FileStream inputStream, FileStream outputStream, byte[] key, byte[] iv, SymmetricAlgorithm symAlgo=null)
        {  
            if(symAlgo==null) symAlgo=new RijndaelManaged();
            symAlgo.Padding = PaddingMode.PKCS7;
            CryptoStream cryptoStream = new CryptoStream(outputStream, symAlgo.CreateDecryptor(key, iv), CryptoStreamMode.Write, true);
            inputStream.CopyTo(cryptoStream);
            cryptoStream.Close();
        }                   

        public static string Decrypt(string encodedStringBase64, byte[] key, byte[] iv, SymmetricAlgorithm symAlgo=null)
        {  
            if(symAlgo==null) symAlgo=new RijndaelManaged();
            MemoryStream memStream = new MemoryStream();
            symAlgo.Padding = PaddingMode.PKCS7;
            CryptoStream cryptoStream = new CryptoStream(memStream, symAlgo.CreateDecryptor(key, iv), CryptoStreamMode.Write, true);
            var encodedBytes = Convert.FromBase64String(encodedStringBase64);
            cryptoStream.Write(encodedBytes, 0, encodedBytes.Length);
            cryptoStream.FlushFinalBlock();
            var decryptedBuffer = memStream.ToArray();
            var decryptedMessage = Encoding.UTF8.GetString(decryptedBuffer);
            memStream.Flush();
            cryptoStream.Flush();            
            memStream.Close();

            return decryptedMessage;
        }
    }
}
