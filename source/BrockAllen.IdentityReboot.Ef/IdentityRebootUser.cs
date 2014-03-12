using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BrockAllen.IdentityReboot.Ef
{
    public class IdentityRebootUser<TKey, TLogin, TRole, TClaim> :
        IdentityUser<TKey, TLogin, TRole, TClaim>, ITwoFactorCode<TKey>
        where TLogin: IdentityUserLogin<TKey> 
        where TRole: IdentityUserRole<TKey> 
        where TClaim: IdentityUserClaim<TKey>
    {
        // ITwoFactorCodeStore
        public string HashedTwoFactorAuthCode { get; set; }
        public DateTime? DateTwoFactorAuthCodeIssued { get; set; }
    }

    public class IdentityRebootUser : IdentityUser, ITwoFactorCode
    {
        // ITwoFactorCodeStore
        public string HashedTwoFactorAuthCode { get; set; }
        public DateTime? DateTwoFactorAuthCodeIssued { get; set; }
    }

}
