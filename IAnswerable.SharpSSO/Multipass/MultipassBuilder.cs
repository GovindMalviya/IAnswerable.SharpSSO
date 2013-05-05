using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using IAnswerable.Utility;
using IAnswerable.SharpSSO.Security;
using System.Web;

namespace IAnswerable.SharpSSO.Multipass
{
    public class MultipassBuilder : IMultipassBuilder
    {
        Encryption encryption = new Encryption();

        public string Serialize<T>(T data)
        {
            return data.JsonSerialize();
        }

        public string Encrypt(string strdata, string initVector, string apikey, string sitekey)
        {
            byte[] bInitVector = initVector.ToByteArray();
            byte[] bData = strdata.ToByteArray();
            byte[] keyBytesLong;
            byte[] keyBytes = new byte[16];


            using (SHA1CryptoServiceProvider sha = new SHA1CryptoServiceProvider())
            {
                keyBytesLong = sha.ComputeHash((apikey + sitekey).ToByteArray());
            }

            Array.Copy(keyBytesLong, keyBytes, 16);

            // XOR first 16 bytes of data
            for (int i = 0; i < 16; i++)
            {
                bData[i] ^= bInitVector[i];
            }


            byte[] encrypted = encryption.AES_Encrypt(bData, keyBytes, bInitVector);

            string encoded = Convert.ToBase64String(encrypted);

            encoded = encoded.Replace("\n", "")     //remove \n
                             .TrimEnd('=')          // remove leading and trailing =
                             .Replace("+", "-")     // replace + with -
                             .Replace("/", "_");    // replace / with _

            return encoded;
        }

        public string GenerateSignature(string text, string apikey)
        {
            string signature = text.ToHMAC_SHA1_Encrypted(apikey);

            return signature;
        }

        public IMultipass Encode(string encrypted, string signature)
        {
            Multipass multipass = new Multipass();

            multipass.MultipassText = encrypted.UrlEncode();
            multipass.Signature = signature.UrlEncode();

            return multipass;
        }
    }
}
