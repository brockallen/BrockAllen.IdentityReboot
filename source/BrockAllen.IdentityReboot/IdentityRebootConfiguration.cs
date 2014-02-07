using System;

namespace BrockAllen.IdentityReboot
{
    public class IdentityRebootConfiguration
    {
        public int PasswordHashIterations { get; set; }
        public int FailedLoginsAllowed { get; set; }
        public TimeSpan FailedLoginLockout { get; set; }
    }
}
