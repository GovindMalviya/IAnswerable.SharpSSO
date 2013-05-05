using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IAnswerable.SharpSSO.Multipass
{
    public interface IDataBuilder
    {
        IMultipass UrlDecode(string multipass, string signature);
        bool IsNotTempered(IMultipass multipass, string apikey);
        string Decrypt(string strdata, string initVector, string apikey, string sitekey);
        T Deserialize<T>(string data);
    }
}
