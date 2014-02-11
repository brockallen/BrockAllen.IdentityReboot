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
    public class MobileStoredTwoFactorCodeProvider<TUser, TKey> : StoredTwoFactorCodeProvider<TUser, TKey>
        where TUser : class, IUser<TKey>
        where TKey : IEquatable<TKey>
    {
        public string MessageFormat { get; set; }

        public override async Task<bool> IsValidProviderForUserAsync(UserManager<TUser, TKey> manager, TUser user)
        {
            var phone = await manager.GetPhoneNumberAsync(user.Id);
            return 
                !String.IsNullOrWhiteSpace(phone) && 
                await base.IsValidProviderForUserAsync(manager, user);
        }

        protected override async Task SendCode(UserManager<TUser, TKey> manager, TUser user, string code)
        {
            await manager.SendSmsAsync(user.Id, String.Format(MessageFormat, code));
        }
    }

    public class MobileStoredTwoFactorCodeProvider<TUser> : 
        MobileStoredTwoFactorCodeProvider<TUser, string>
        where TUser : class, IUser<string>
    {
    }
}
