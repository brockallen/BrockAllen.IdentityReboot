using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Data.Entity;
using System.Threading.Tasks;

namespace BrockAllen.IdentityReboot.Ef
{
    public class IdentityRebootUserStore<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim> : 
        UserStore<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim>, 
        ITwoFactorCodeStore<TUser, TKey>
        where TUser : IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>, ITwoFactorCode<TKey>
        where TRole: IdentityRole<TKey, TUserRole> 
        where TKey: IEquatable<TKey> 
        where TUserLogin: IdentityUserLogin<TKey>, new() 
        where TUserRole: IdentityUserRole<TKey>, new() 
        where TUserClaim: IdentityUserClaim<TKey>, new()
    {
        public IdentityRebootUserStore(DbContext ctx)
            : base(ctx)
        {
        }

        public Task<TwoFactorAuthData> GetTwoFactorAuthDataAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (user.DateTwoFactorAuthCodeIssued == null || 
                String.IsNullOrWhiteSpace(user.HashedTwoFactorAuthCode))
            {
                return null;
            }

            return Task.FromResult(new TwoFactorAuthData{ 
                HashedCode = user.HashedTwoFactorAuthCode,
                DateIssued = user.DateTwoFactorAuthCodeIssued.Value
            });
        }

        public Task SetTwoFactorAuthDataAsync(TUser user, TwoFactorAuthData data)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (data == null)
            {
                throw new ArgumentNullException("data");
            }

            user.HashedTwoFactorAuthCode = data.HashedCode;
            user.DateTwoFactorAuthCodeIssued = data.DateIssued;

            return Task.FromResult(0);
        }
    }
    
    public class IdentityRebootUserStore<TUser> :
        IdentityRebootUserStore<TUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>,
        IUserStore<TUser>,
        IUserStore<TUser, string>,
        IDisposable
        where TUser : IdentityUser, ITwoFactorCode
    {
        public IdentityRebootUserStore(DbContext ctx)
            : base(ctx)
        {
        }
    }
}
