using System;

namespace BrockAllen.IdentityReboot
{
    public class FailedLoginAttempts
    {
        public int Count { get; set; }
        public DateTime? LastFailedDate { get; set; }
    }
}
