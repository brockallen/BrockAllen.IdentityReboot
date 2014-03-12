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
        public IdentityRebootUserManager(IUserStore<TUser, TKey> store)
            : this(store, null)
        {
        }

        public IdentityRebootUserManager(IUserStore<TUser, TKey> store, IdentityRebootConfiguration config)
            : base(store)
        {
            if (config == null)
            {
                this.PasswordHasher = new AdaptivePasswordHasher();
            }
            else
            {
                config.Validate();
                if (config.PasswordHashingDuration > TimeSpan.Zero)
                {
                    this.PasswordHasher = new AdaptivePasswordHasher(config.PasswordHashingDuration);
                }
                else
                {
                    this.PasswordHasher = new AdaptivePasswordHasher(config.PasswordHashIterations);
                }
            }
        }

        protected virtual DateTime UtcNow
        {
            get
            {
                return DateTime.UtcNow;
            }
        }

        public override async Task<string> GenerateChangePhoneNumberTokenAsync(TKey userId, string phoneNumber)
        {
            var provider = new MobileStoredTwoFactorCodeProvider<TUser, TKey>();
            return await provider.GenerateAsync("changephone" + phoneNumber, this, this.FindById(userId));
        }

        public override async Task<bool> VerifyChangePhoneNumberTokenAsync(TKey userId, string token, string phoneNumber)
        {
            var provider = new MobileStoredTwoFactorCodeProvider<TUser, TKey>();
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
