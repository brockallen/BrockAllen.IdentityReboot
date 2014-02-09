using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BrockAllen.IdentityReboot
{
    public class TwoFactorAuthData
    {
        public string HashedCode { get; set; }
        public DateTime DateIssued { get; set; }
    }
}
