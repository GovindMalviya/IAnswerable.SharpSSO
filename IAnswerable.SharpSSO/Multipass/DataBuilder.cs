using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IAnswerable.Utility;
using System.Security.Cryptography;
using IAnswerable.SharpSSO.Security;

namespace IAnswerable.SharpSSO.Multipass
{
    public class DataBuilder : IDataBuilder
    {
        Encryption encryption = new Encryption();

        public IMultipass UrlDecode(string multipass, string signature)
        {
            IMultipass _multipass = new Multipass();
            _multipass.MultipassText = multipass.UrlDecode();
            _multipass.Signature = signature.UrlDecode();

            return _multipass;
        }

        public bool IsNotTempered(IMultipass multipass, string _apikey)
        {
             string signature = multipass.MultipassText.ToHMAC_SHA1_Encrypted(_apikey);

             return signature == multipass.Signature;
        }

        public string Decrypt(string strdata, string initVector, string apikey, string sitekey)
        {
           strdata = strdata.Replace("-", "+")  // replace - with +
                             .Replace("_", "/") // replace _ with /
                             + "=";             // add = to end of string


            byte[] bInitVector = initVector.ToByteArray();
            byte[] bData = Convert.FromBase64String(strdata);
            byte[] keyBytesLong;
            byte[] keyBytes = new byte[16];


            using (SHA1CryptoServiceProvider sha = new SHA1CryptoServiceProvider())
            {
                keyBytesLong = sha.ComputeHash((apikey + sitekey).ToByteArray());
            }

            Array.Copy(keyBytesLong, keyBytes, 16);

          

            byte[] decrypted = encryption.AES_Decrypt(bData, keyBytes, bInitVector);

            // XOR first 16 bytes of data
            for (int i = 0; i < 16; i++)
            {
                decrypted[i] ^= bInitVector[i];
            }

            string decoded = System.Text.Encoding.Default.GetString(decrypted);


            return decoded;
        }

        public T Deserialize<T>(string data)
        {
            return data.JsonDeserialize<T>();
        }
    }
}
