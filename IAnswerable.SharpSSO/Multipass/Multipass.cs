using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IAnswerable.SharpSSO.Multipass
{
    public class Multipass : IMultipass
    {
        public string MultipassText
        {
            get;
            set;
        }

        public string Signature
        {
            get;
            set;
        }
    }
}
