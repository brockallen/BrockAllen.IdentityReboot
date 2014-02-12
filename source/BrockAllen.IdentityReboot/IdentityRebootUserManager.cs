using Microsoft.AspNet.Identity;
using System;
using System.Threading.Tasks;

namespace BrockAllen.IdentityReboot
{
    public class IdentityRebootUserManager<TUser, TKey> : 
        UserManager<TUser, TKey>,
        IUserManagerSupportsTwoFactorAuthStore<TUser, TKey>
        where TUser : class, IUser<TKey>
        where TKey : IEquatable<TKey>
    {
        const int DefailtFailedLoginsAllowed = 5;
        static readonly TimeSpan DefaultFailedLoginLockout = TimeSpan.FromMinutes(5);

        public int FailedLoginsAllowed { get; set; }
        public TimeSpan FailedLoginLockout { get; set; }

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
                    FailedLoginLockout = DefaultFailedLoginLockout
                };
            }

            if (config.FailedLoginsAllowed <= 0)
            {
                config.FailedLoginsAllowed = DefailtFailedLoginsAllowed;
            }
            
            this.FailedLoginsAllowed = config.FailedLoginsAllowed;
            this.FailedLoginLockout = config.FailedLoginLockout;
            
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
            return this.Store as IPasswordBruteForcePreventionStore<TUser, TKey>;
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
            if (store == null) return false;

            var failedLoginAttempts = await store.GetFailedLoginAttemptsAsync(user);
            if (failedLoginAttempts == null)
            {
                failedLoginAttempts = new FailedLoginAttempts();
            }

            bool result = false;
            if (this.FailedLoginsAllowed <= failedLoginAttempts.Count)
            {
                result = failedLoginAttempts.LastFailedDate > UtcNow.Subtract(this.FailedLoginLockout);
                if (!result)
                {
                    // this resets the attempts once outside the lockout window
                    await ResetPasswordFailureAsync(user);
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

        protected virtual async Task ResetPasswordFailureAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var hasPassword = await this.HasPasswordAsync(user.Id);
            if (!hasPassword) return;

            var store = GetPasswordBruteForcePreventionStore();
            if (store == null) return;

            var failedLoginAttempts = await store.GetFailedLoginAttemptsAsync(user);
            if (failedLoginAttempts == null)
            {
                failedLoginAttempts = new FailedLoginAttempts();
            }

            if (failedLoginAttempts.Count != 0 || failedLoginAttempts.LastFailedDate != null)
            {
                failedLoginAttempts.Count = 0;
                failedLoginAttempts.LastFailedDate = null;

                await store.SetFailedLoginAttemptsAsync(user, failedLoginAttempts);
                await this.UpdateAsync(user);
            }
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
            if (store == null) return;

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

        protected override async Task<bool> VerifyPassword(IUserPasswordStore<TUser, TKey> store, TUser user, string password)
        {
            if (await HasTooManyPasswordFailuresAsync(user))
            {
                return false;
            }
            
            var result = await base.VerifyPassword(store, user, password);
            if (result)
            {
                await ResetPasswordFailureAsync(user);
            }
            else
            {
                await RecordPasswordFailureAsync(user);
            }

            return result;
        }

        public override async Task<bool> VerifyTwoFactorTokenAsync(TKey userId, string twoFactorProvider, string token)
        {
            var user = this.FindById(userId);
            if (user != null && await HasTooManyPasswordFailuresAsync(user))
            {
                return false;
            }

            var result = await base.VerifyTwoFactorTokenAsync(userId, twoFactorProvider, token);
            if (user != null)
            {
                if (result)
                {
                    await ResetPasswordFailureAsync(user);
                }
                else
                {
                    await RecordPasswordFailureAsync(user);
                }
            }

            return result;
        }

        public override async Task<string> GenerateChangePhoneNumberTokenAsync(TKey userId, string phoneNumber)
        {
            var provider = new StoredTwoFactorCodeProvider<TUser, TKey>();
            return await provider.GenerateAsync("changephone" + phoneNumber, this, this.FindById(userId));
        }

        public override async Task<bool> VerifyChangePhoneNumberTokenAsync(TKey userId, string token, string phoneNumber)
        {
            var provider = new StoredTwoFactorCodeProvider<TUser, TKey>();
            return await provider.ValidateAsync("changephone" + phoneNumber, token, this, this.FindById(userId));
        }

        bool IUserManagerSupportsTwoFactorAuthStore<TUser, TKey>.IsSupported()
        {
            return this.Store is ITwoFactorCodeStore<TUser, TKey>;
        }

        Task<TwoFactorAuthData> IUserManagerSupportsTwoFactorAuthStore<TUser, TKey>.GetTwoFactorAuthDataAsync(TUser user)
        {
            var store = this.Store as ITwoFactorCodeStore<TUser, TKey>;
            if (store == null) throw new InvalidOperationException(Messages.ITwoFactorCodeStoreNotImplemented);

            return store.GetTwoFactorAuthDataAsync(user);
        }

        Task IUserManagerSupportsTwoFactorAuthStore<TUser, TKey>.SetTwoFactorAuthDataAsync(TUser user, TwoFactorAuthData data)
        {
            var store = this.Store as ITwoFactorCodeStore<TUser, TKey>;
            if (store == null) throw new InvalidOperationException(Messages.ITwoFactorCodeStoreNotImplemented);

            return store.SetTwoFactorAuthDataAsync(user, data);
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
