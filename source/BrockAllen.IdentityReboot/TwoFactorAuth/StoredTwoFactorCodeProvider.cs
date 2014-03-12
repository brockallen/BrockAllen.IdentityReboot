using BrockAllen.IdentityReboot.Internal;
using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace BrockAllen.IdentityReboot
{
    public abstract class StoredTwoFactorCodeProvider<TUser, TKey> : IUserTokenProvider<TUser, TKey>
        where TUser : class, IUser<TKey>
        where TKey : IEquatable<TKey>
    {
        const int DefaultDigitLength = 6;
        const int DefaultHashIterations = 10000;
        static readonly TimeSpan DefaultValidityDuration = TimeSpan.FromMinutes(5);

        public int Digits { get; set; }
        public int HashingIterations { get; set; }
        public TimeSpan ValidityDuration { get; set; }

        public StoredTwoFactorCodeProvider()
        {
            Digits = DefaultDigitLength;
            HashingIterations = DefaultHashIterations;
            ValidityDuration = DefaultValidityDuration;
        }

        public async Task<string> GenerateAsync(string purpose, UserManager<TUser, TKey> manager, TUser user)
        {
            var twoFactAuthManager = manager as IUserManagerSupportsTwoFactorAuthStore<TUser, TKey>;
            if (twoFactAuthManager == null) throw new InvalidOperationException(Messages.IUserManagerSupportsTwoFactorAuthStoreNotImplemented);
            if (!twoFactAuthManager.IsSupported()) throw new InvalidOperationException(Messages.ITwoFactorCodeStoreNotImplemented);

            var stamp = await manager.GetSecurityStampAsync(user.Id);
            purpose += stamp;

            var bytes = Crypto.GenerateSaltInternal(sizeof(long));
            var val = BitConverter.ToInt64(bytes, 0);
            var mod = (int)Math.Pow(10, Digits);
            val %= mod;
            val = Math.Abs(val);

            var code = val.ToString("D" + Digits);

            var hasher = new AdaptivePasswordHasher(this.HashingIterations);
            var hashedCode = hasher.HashPassword(purpose + code);

            var data = new TwoFactorAuthData { HashedCode = hashedCode, DateIssued = UtcNow };
            await twoFactAuthManager.SetTwoFactorAuthDataAsync(user, data);
            await manager.UpdateAsync(user);

            return code;
        }

        public virtual Task<bool> IsValidProviderForUserAsync(UserManager<TUser, TKey> manager, TUser user)
        {
            var twoFactAuthManager = manager as IUserManagerSupportsTwoFactorAuthStore<TUser, TKey>;
            return Task.FromResult(twoFactAuthManager != null && twoFactAuthManager.IsSupported());
        }

        public abstract Task NotifyAsync(string token, UserManager<TUser, TKey> manager, TUser user);

        public async Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser, TKey> manager, TUser user)
        {
            var twoFactAuthManager = manager as IUserManagerSupportsTwoFactorAuthStore<TUser, TKey>;
            if (twoFactAuthManager == null) throw new InvalidOperationException(Messages.IUserManagerSupportsTwoFactorAuthStoreNotImplemented);
            if (!twoFactAuthManager.IsSupported()) throw new InvalidOperationException(Messages.ITwoFactorCodeStoreNotImplemented);

            var data = await twoFactAuthManager.GetTwoFactorAuthDataAsync(user);
            if (data != null &&
                data.HashedCode != null &&
                UtcNow < data.DateIssued.Add(this.ValidityDuration))
            {
                var stamp = await manager.GetSecurityStampAsync(user.Id);
                purpose += stamp;

                var hasher = new AdaptivePasswordHasher(this.HashingIterations);
                return hasher.VerifyHashedPassword(data.HashedCode, purpose + token) != PasswordVerificationResult.Failed;
            }

            return false;
        }

        protected virtual DateTime UtcNow
        {
            get { return DateTime.UtcNow; }
        }
    }

    public abstract class StoredTwoFactorCodeProvider<TUser> : StoredTwoFactorCodeProvider<TUser, string>
        where TUser : class, IUser<string>
    {
    }
}
