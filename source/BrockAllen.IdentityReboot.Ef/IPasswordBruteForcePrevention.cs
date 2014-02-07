using Microsoft.AspNet.Identity;
using System;

namespace BrockAllen.IdentityReboot.Ef
{
    public interface IPasswordBruteForcePrevention : IUser
    {
        int FailedLoginCount { get; set; }
        DateTime? LastFailedLogin { get; set; }
    }
}
