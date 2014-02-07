using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Data.Entity;
using System.Threading.Tasks;

namespace BrockAllen.IdentityReboot.Ef
{
    public class IdentityRebootUserStore<TUser> : UserStore<TUser>, IPasswordBruteForcePreventionStore<TUser>
        where TUser : IdentityUser, IPasswordBruteForcePrevention
    {
        public IdentityRebootUserStore(DbContext ctx)
            : base(ctx)
        {
        }

        public Task<FailedLoginAttempts> GetFailedLoginAttemptsAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult<FailedLoginAttempts>(new FailedLoginAttempts{
                Count = user.FailedLoginCount, 
                LastFailedDate = user.LastFailedLogin
            });
        }

        public Task SetFailedLoginAttemptsAsync(TUser user, FailedLoginAttempts attempts)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (attempts == null)
            {
                throw new ArgumentNullException("attempts");
            }
            
            user.FailedLoginCount = attempts.Count;
            user.LastFailedLogin = attempts.LastFailedDate;

            return Task.FromResult(0);
        }
    }
}
