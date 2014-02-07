using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BrockAllen.IdentityReboot
{
    public class FailedLoginAttempts
    {
        public int Count { get; set; }
        public DateTime? LastFailedDate { get; set; }
    }

    public interface IPasswordBruteForcePreventionStore<TUser> : IUserStore<TUser>
        where TUser : IUser
    {
        Task<FailedLoginAttempts> GetFailedLoginAttemptsAsync(TUser user);
        Task SetFailedLoginAttemptsAsync(TUser user, FailedLoginAttempts attempts);
    }
}
