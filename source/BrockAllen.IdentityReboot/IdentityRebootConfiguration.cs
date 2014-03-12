using System;

namespace BrockAllen.IdentityReboot
{
    public class IdentityRebootConfiguration
    {
        public int PasswordHashIterations { get; set; }
        public TimeSpan PasswordHashingDuration { get; set; }

        internal void Validate()
        {
            if (PasswordHashingDuration > TimeSpan.Zero && PasswordHashIterations > 0)
            {
                throw new Exception("IdentityRebootConfiguration can only have either PasswordHashIterations or PasswordHashingDuration set.");
            }
        }
    }
}
