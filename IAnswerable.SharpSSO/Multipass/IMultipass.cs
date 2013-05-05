using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IAnswerable.SharpSSO.Multipass
{
    public interface IMultipass
    {
        string MultipassText { get; set; }
        string Signature { get; set; }
    }
}
