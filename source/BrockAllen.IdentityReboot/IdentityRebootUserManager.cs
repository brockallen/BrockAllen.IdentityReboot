using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BrockAllen.IdentityReboot
{
    public class IdentityRebootUserManager<TUser> : UserManager<TUser>
        where TUser : IUser
    {
        public IdentityRebootConfiguration Configuration { get; private set; }

        public IdentityRebootUserManager(IUserStore<TUser> store)
            : this(store, null)
        {
        }

        public IdentityRebootUserManager(IUserStore<TUser> store, IdentityRebootConfiguration config)
            : base(store)
        {
            if (config == null)
            {
                config = new IdentityRebootConfiguration()
                {
                    FailedLoginLockout = TimeSpan.FromMinutes(5)
                };
            }

            if (config.FailedLoginsAllowed <= 0)
            {
                config.FailedLoginsAllowed = 5;
            }
            
            this.Configuration = config;
            this.PasswordHasher = new AdaptivePasswordHasher(config.PasswordHashIterations);
        }

        protected virtual DateTime UtcNow
        {
            get
            {
                return DateTime.UtcNow;
            }
        }

        IPasswordBruteForcePreventionStore<TUser> GetPasswordBruteForcePreventionStore()
        {
            var store = this.Store as IPasswordBruteForcePreventionStore<TUser>;
            if (store == null)
            {
                throw new NotImplementedException(Messages.IPasswordBruteForcePreventionStoreNotImplemented);
            }
            return store;
        }

        protected async virtual Task<bool> HasTooManyPasswordFailures(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var store = GetPasswordBruteForcePreventionStore();
            var failedLoginAttempts = await store.GetFailedLoginAttemptsAsync(user);

            bool result = false;
            if (Configuration.FailedLoginsAllowed <= failedLoginAttempts.Count)
            {
                result = failedLoginAttempts.LastFailedDate >= UtcNow.Subtract(Configuration.FailedLoginLockout);
            }

            if (result)
            {
                failedLoginAttempts.Count++;
                await store.SetFailedLoginAttemptsAsync(user, failedLoginAttempts);
            }

            return result;
        }
        
        protected async virtual Task RecordPasswordFailure(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var store = GetPasswordBruteForcePreventionStore();
            var failedLoginAttempts = await store.GetFailedLoginAttemptsAsync(user);

            if (failedLoginAttempts.Count <= 0)
            {
                failedLoginAttempts.Count = 1;
            }
            else
            {
                failedLoginAttempts.Count++;
            }
            
            failedLoginAttempts.LastFailedDate = UtcNow;
            
            await store.SetFailedLoginAttemptsAsync(user, failedLoginAttempts);
        }

        public async override Task<TUser> FindAsync(string userName, string password)
        {
            var user = await base.FindByNameAsync(userName);
            if (user != null)
            {
                if (await HasTooManyPasswordFailures(user))
                {
                    return default(TUser);
                }
            }
            
            var result = await base.FindAsync(userName, password);
            if (result == null && user != null)
            {
                await RecordPasswordFailure(user);
            }
            return result;
        }

        public async override Task<IdentityResult> ChangePasswordAsync(string userId, string currentPassword, string newPassword)
        {
            var user = await base.FindByIdAsync(userId);
            if (user != null)
            {
                if (await HasTooManyPasswordFailures(user))
                {
                    return IdentityResult.Failed(Messages.TooManyFailedPasswords);
                }
            }

            var result = await base.ChangePasswordAsync(userId, currentPassword, newPassword);
            if (!result.Succeeded)
            {
                var validation = await this.PasswordValidator.ValidateAsync(newPassword);
                if (validation.Succeeded)
                {
                    await RecordPasswordFailure(user);
                }
            }
            return result;
        }
    }
}
