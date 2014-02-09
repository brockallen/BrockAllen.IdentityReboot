using Microsoft.AspNet.Identity;
using System.Threading.Tasks;

namespace BrockAllen.IdentityReboot
{
    public interface IPasswordBruteForcePreventionStore<TUser, TKey> : IUserStore<TUser, TKey>
        where TUser : class, IUser<TKey>
    {
        Task<FailedLoginAttempts> GetFailedLoginAttemptsAsync(TUser user);
        Task SetFailedLoginAttemptsAsync(TUser user, FailedLoginAttempts attempts);
    }
}
