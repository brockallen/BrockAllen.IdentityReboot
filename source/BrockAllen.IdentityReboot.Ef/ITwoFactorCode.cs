using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BrockAllen.IdentityReboot.Ef
{
    public interface ITwoFactorCode<TKey> : IUser<TKey>
    {
        string HashedTwoFactorAuthCode { get; set; }
        DateTime? DateTwoFactorAuthCodeIssued { get; set; }
    }

    public interface ITwoFactorCode : ITwoFactorCode<string>
    {
    }
}
