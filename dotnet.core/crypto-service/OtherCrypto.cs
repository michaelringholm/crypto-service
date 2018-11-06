using System;
using System.IO;
using System.Security.Cryptography;
using System.Net.Sockets;
using System.Text;

namespace pem_console
{
    public class OtherCrypto
    {
        public static byte[] encrypt()
        {
            //Create a network stream from the TCP connection.   
            //MemoryStream NetStream = new MemoryStream();
            FileStream NetStream = new FileStream("temp-stream", FileMode.OpenOrCreate);

            //Create a new instance of the RijndaelManaged class  
            // and encrypt the stream.  
            RijndaelManaged RMCrypto = new RijndaelManaged();

            byte[] Key = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
            byte[] IV = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

            //Create a CryptoStream, pass it the NetworkStream, and encrypt   
            //it with the Rijndael class.  
            CryptoStream CryptStream = new CryptoStream(NetStream,
            RMCrypto.CreateEncryptor(Key, IV),
            CryptoStreamMode.Write);

            //Create a StreamWriter for easy writing to the   
            //network stream.  
            StreamWriter SWriter = new StreamWriter(CryptStream);

            //Write to the stream.  
            SWriter.WriteLine("Hello World!");
            

            //Inform the user that the message was written  
            //to the stream.  
            Console.WriteLine("The message was sent.");

            //Close all the connections.  
            SWriter.Close();
            CryptStream.Close();

            // MRS
            //var encodedBytes = NetStream.GetBuffer();
            //var encodedStringBase64 = Convert.ToBase64String(encodedBytes);

            NetStream.Close();

            // MRS
            return null;
        }


        public static string decrypt(byte[] encodedBytes)
        {
            //The key and IV must be the same values that were used  
            //to encrypt the stream.    
            byte[] Key = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
            byte[] IV = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
            //Create a network stream from the connection.  
            //MemoryStream NetStream = new MemoryStream();
            //MemoryStream NetStream = new MemoryStream(Convert.FromBase64String(encodedStringBase64));
            //MemoryStream NetStream = new MemoryStream(encodedBytes);
            //StringStream
            //File.WriteAllBytes("temp-stream", encodedBytes);
            FileStream NetStream = new FileStream("temp-stream", FileMode.Open);

            //Create a new instance of the RijndaelManaged class  
            // and decrypt the stream.  
            RijndaelManaged RMCrypto = new RijndaelManaged();

            //Create a CryptoStream, pass it the NetworkStream, and decrypt   
            //it with the Rijndael class using the key and IV.  
            CryptoStream CryptStream = new CryptoStream(NetStream,
               RMCrypto.CreateDecryptor(Key, IV),
               CryptoStreamMode.Read);

            //Read the stream.  
            StreamReader SReader = new StreamReader(CryptStream);

            // MRS
            //NetStream.Write(Convert.FromBase64String(encodedStringBase64));               
            //NetStream.Write(Convert.FromBase64String(encodedStringBase64));               

            //Display the message.  
            // MRS
            //NetStream.Flush();
            //byte[] buf = new byte[256];
            //CryptStream.Read(buf, 0, 256);
            //char[] charBuf = new char[256];
            //var decryptedMessage = SReader.Read(charBuf, 0, 256);
            var decryptedMessage = SReader.ReadToEnd();
            Console.WriteLine("The decrypted original message: {0}", decryptedMessage);

            //Close the streams.  
            SReader.Close();
            NetStream.Close();

            return null;
            //return decryptedMessage;
        }
    }
}