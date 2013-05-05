using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IAnswerable.Utility;
using System.Security.Cryptography;
using IAnswerable.SharpSSO.Security;

namespace IAnswerable.SharpSSO.Multipass
{
    public class Receiver<T> where T : class, new()
    {
        string _apikey;
        string _sitekey;
        string _initVector;
        DataBuilder _databuilder = new DataBuilder();
        Encryption encryption = new Encryption();

        public string ApiKey
        {
            private get
            {
                return _apikey;
            }
            set
            {
                _apikey = value;
            }
        }

        public string SiteKey
        {
            private get
            {
                return _sitekey;
            }
            set
            {
                _sitekey = value;
            }
        }

        public string InitVector
        {
            private get
            {
                return _initVector;
            }
            set
            {
                _initVector = value;
            }
        }

        public Receiver()
        {
            

        }

        public T GetData(string multipass, string signature)
        {

            IMultipass _multipass = _databuilder.UrlDecode(multipass, signature);

            if (_databuilder.IsNotTempered(_multipass,_apikey))
            {
                string decoded = _databuilder.Decrypt(_multipass.MultipassText, _initVector, _apikey, _sitekey);

                T data = _databuilder.Deserialize<T>(decoded);

                return data;
            }

            return default(T);
        }

   
    }
}
