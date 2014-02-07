using Microsoft.AspNet.Identity;
using System;
using System.Threading.Tasks;

namespace BrockAllen.IdentityReboot
{
    public class IdentityRebootUserManager<TUser, TKey> : UserManager<TUser, TKey>
        where TUser : class, IUser<TKey>
        where TKey : IEquatable<TKey>
    {
        public IdentityRebootConfiguration Configuration { get; private set; }

        public IdentityRebootUserManager(IUserStore<TUser, TKey> store)
            : this(store, null)
        {
        }

        public IdentityRebootUserManager(IUserStore<TUser, TKey> store, IdentityRebootConfiguration config)
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

        IPasswordBruteForcePreventionStore<TUser, TKey> GetPasswordBruteForcePreventionStore()
        {
            var store = this.Store as IPasswordBruteForcePreventionStore<TUser, TKey>;
            if (store == null)
            {
                throw new NotImplementedException(Messages.IPasswordBruteForcePreventionStoreNotImplemented);
            }
            return store;
        }

        protected async virtual Task<bool> HasTooManyPasswordFailuresAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var hasPassword = await this.HasPasswordAsync(user.Id);
            if (!hasPassword) return false;

            var store = GetPasswordBruteForcePreventionStore();
            var failedLoginAttempts = await store.GetFailedLoginAttemptsAsync(user);
            if (failedLoginAttempts == null)
            {
                failedLoginAttempts = new FailedLoginAttempts();
            }

            bool result = false;
            if (Configuration.FailedLoginsAllowed <= failedLoginAttempts.Count)
            {
                result = failedLoginAttempts.LastFailedDate >= UtcNow.Subtract(Configuration.FailedLoginLockout);
                if (!result)
                {
                    // this resets the attempts once outside the lockout window
                    failedLoginAttempts.Count = 0;
                    await store.SetFailedLoginAttemptsAsync(user, failedLoginAttempts);
                    await this.UpdateAsync(user);
                }
            }

            if (result)
            {
                // record the attempt, but don't update the time
                failedLoginAttempts.Count++;
                await store.SetFailedLoginAttemptsAsync(user, failedLoginAttempts);
                await this.UpdateAsync(user);
            }

            return result;
        }
        
        protected async virtual Task RecordPasswordFailureAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var hasPassword = await this.HasPasswordAsync(user.Id);
            if (!hasPassword) return;

            var store = GetPasswordBruteForcePreventionStore();
            var failedLoginAttempts = await store.GetFailedLoginAttemptsAsync(user);
            if (failedLoginAttempts == null)
            {
                failedLoginAttempts = new FailedLoginAttempts();
            }

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
            await this.UpdateAsync(user);
        }

        public async override Task<TUser> FindAsync(string userName, string password)
        {
            var user = await base.FindByNameAsync(userName);
            if (user != null)
            {
                if (await HasTooManyPasswordFailuresAsync(user))
                {
                    return default(TUser);
                }
            }
            
            var result = await base.FindAsync(userName, password);
            if (result == null && user != null)
            {
                await RecordPasswordFailureAsync(user);
            }

            return result;
        }

        public override async Task<IdentityResult> ChangePasswordAsync(TKey userId, string currentPassword, string newPassword)
        {
            var user = await base.FindByIdAsync(userId);
            if (user != null)
            {
                if (await HasTooManyPasswordFailuresAsync(user))
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
                    await RecordPasswordFailureAsync(user);
                }
            }

            return result;
        }
    }

    public class IdentityRebootUserManager<TUser> :
        IdentityRebootUserManager<TUser, string>
        where TUser : class, IUser<string>
    {
        public IdentityRebootUserManager(IUserStore<TUser> store)
            : this(store, null)
        {
        }
        
        public IdentityRebootUserManager(IUserStore<TUser> store, IdentityRebootConfiguration config)
            : base(store, config)
        {
        }
    }
}
