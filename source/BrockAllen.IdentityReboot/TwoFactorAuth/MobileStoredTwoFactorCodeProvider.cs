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

        public async override Task<bool> IsValidProviderForUserAsync(UserManager<TUser, TKey> manager, TUser user)
        {
            return 
                await base.IsValidProviderForUserAsync(manager, user) &&
                !String.IsNullOrWhiteSpace(await manager.GetPhoneNumberAsync(user.Id)) &&
                await manager.IsPhoneNumberConfirmedAsync(user.Id);
        }

        public async override Task NotifyAsync(string token, UserManager<TUser, TKey> manager, TUser user)
        {
            var msg = token;
            if (MessageFormat != null)
            {
                msg = String.Format(MessageFormat, token);
            }
            await manager.SendSmsAsync(user.Id, msg);
        }
    }

    public class MobileStoredTwoFactorCodeProvider<TUser> : 
        MobileStoredTwoFactorCodeProvider<TUser, string>
        where TUser : class, IUser<string>
    {
    }
}
