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
        IdentityUser<TKey, TLogin, TRole, TClaim>, IPasswordBruteForcePrevention<TKey>, ITwoFactorCode<TKey>
        where TLogin: IdentityUserLogin<TKey> 
        where TRole: IdentityUserRole<TKey> 
        where TClaim: IdentityUserClaim<TKey>
    {
        // IPasswordBruteForcePreventionStore
        public virtual int FailedLoginCount { get; set; }
        public virtual DateTime? LastFailedLogin { get; set; }

        // ITwoFactorCodeStore
        public string HashedTwoFactorAuthCode { get; set; }
        public DateTime? DateTwoFactorAuthCodeIssued { get; set; }
    }

    public class IdentityRebootUser : IdentityUser, IPasswordBruteForcePrevention, ITwoFactorCode
    {
        // IPasswordBruteForcePreventionStore
        public virtual int FailedLoginCount { get; set; }
        public virtual DateTime? LastFailedLogin { get; set; }

        // ITwoFactorCodeStore
        public string HashedTwoFactorAuthCode { get; set; }
        public DateTime? DateTwoFactorAuthCodeIssued { get; set; }
    }

}
