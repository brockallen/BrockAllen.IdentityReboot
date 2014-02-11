using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BrockAllen.IdentityReboot
{
    public interface ITwoFactorCodeStore<TUser, TKey> : IUserStore<TUser, TKey>
        where TUser : class, IUser<TKey>
    {
        Task<TwoFactorAuthData> GetTwoFactorAuthDataAsync(TUser user);
        Task SetTwoFactorAuthDataAsync(TUser user, TwoFactorAuthData data);
    }
}
