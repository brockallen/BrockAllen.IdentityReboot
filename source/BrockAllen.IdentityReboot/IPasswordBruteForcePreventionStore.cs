using Microsoft.AspNet.Identity;
using System.Threading.Tasks;

namespace BrockAllen.IdentityReboot
{
    public interface IPasswordBruteForcePreventionStore<TUser> : IUserStore<TUser>
        where TUser : IUser
    {
        Task<FailedLoginAttempts> GetFailedLoginAttemptsAsync(TUser user);
        Task SetFailedLoginAttemptsAsync(TUser user, FailedLoginAttempts attempts);
    }
}
