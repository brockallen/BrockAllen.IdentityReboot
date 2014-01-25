using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BrockAllen.IdentityReboot
{
    public class IdentityRebootConfiguration
    {
        public int PasswordHashIterations { get; set; }
        public int FailedLoginsAllowed { get; set; }
        public TimeSpan FailedLoginLockout { get; set; }
    }
}
