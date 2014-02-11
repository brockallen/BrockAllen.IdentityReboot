using Microsoft.AspNet.Identity;
using System;

namespace BrockAllen.IdentityReboot.Ef
{
    public interface IPasswordBruteForcePrevention<TKey> : IUser<TKey>
    {
        int FailedLoginCount { get; set; }
        DateTime? LastFailedLogin { get; set; }
    }
    
    public interface IPasswordBruteForcePrevention : IPasswordBruteForcePrevention<string>
    {
    }
}
