using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class SymmetricCryptoService
{
    public String Encrypt(string data, string password, string salt)
    {
        var symAlgo = new RijndaelManaged();
        byte[] saltBytes = Encoding.UTF8.GetBytes(salt);
        Rfc2898DeriveBytes theKey = new Rfc2898DeriveBytes(password, saltBytes);
        symAlgo.Key = theKey.GetBytes(symAlgo.KeySize / 8);
        symAlgo.IV = theKey.GetBytes(symAlgo.BlockSize / 8);
        symAlgo.Padding = PaddingMode.None;
        ICryptoTransform encryptor = symAlgo.CreateEncryptor();
        var outStream = new MemoryStream();
        CryptoStream encryptStream = new CryptoStream(outStream, encryptor, CryptoStreamMode.Write);
        encryptStream.Write(Encoding.UTF8.GetBytes(data), 0, data.Length);
        encryptStream.Close();
        var encryptedDataBase64 = Convert.ToBase64String(outStream.GetBuffer());        
        return encryptedDataBase64;
    }

    public String Decrypt(string encryptedDataBase64, string password, string salt)
    {
        var symAlgo = new RijndaelManaged();
        byte[] saltBytes = Encoding.UTF8.GetBytes(salt);
        Rfc2898DeriveBytes theKey = new Rfc2898DeriveBytes(password, saltBytes);
        symAlgo.Key = theKey.GetBytes(symAlgo.KeySize / 8);
        symAlgo.IV = theKey.GetBytes(symAlgo.BlockSize / 8);
        symAlgo.Padding = PaddingMode.None;
        ICryptoTransform decryptor = symAlgo.CreateDecryptor();
        var encryptedBytes = Convert.FromBase64String(encryptedDataBase64);
        var inStream = new MemoryStream(encryptedBytes);
        CryptoStream decryptStream = new CryptoStream(inStream, decryptor, CryptoStreamMode.Read);
        byte[] decryptedDataBytes = new byte[encryptedBytes.Length];
        decryptStream.Read(decryptedDataBytes, 0, (int)encryptedBytes.Length);
        decryptStream.Close();
        var decryptedData = Encoding.UTF8.GetString(decryptedDataBytes);
        return decryptedData;
    }
}