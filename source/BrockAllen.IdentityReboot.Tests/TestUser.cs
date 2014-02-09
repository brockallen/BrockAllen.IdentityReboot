using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BrockAllen.IdentityReboot.Tests
{
    public class TestUser : IUser
    {
        public string Id { get; set; }
        public string UserName { get; set; }
        public string PasswordHash { get; set; }
        public string SecurityStamp { get; set; }
        public string MobilePhone { get; set; }
        public bool MobilePhoneConfirmed { get; set; }

        public int FailedLoginCount { get; set; }
        public DateTime? LastFailedLogin { get; set; }
    }

    public class TestUserStore : 
        IUserStore<TestUser>, 
        IUserPasswordStore<TestUser>, 
        IUserSecurityStampStore<TestUser>,
        IUserPhoneNumberStore<TestUser>,
        IPasswordBruteForcePreventionStore<TestUser, string>
    {
        List<TestUser> users = new List<TestUser>();
        public Task CreateAsync(TestUser user)
        {
            user.Id = Guid.NewGuid().ToString();
            users.Add(user);
            return Task.FromResult(0);
        }

        public Task DeleteAsync(TestUser user)
        {
            users.Remove(user);
            return Task.FromResult(0);
        }

        public Task<TestUser> FindByIdAsync(string userId)
        {
            var user = users.SingleOrDefault(x => x.Id == userId);
            return Task.FromResult(user);
        }

        public Task<TestUser> FindByNameAsync(string userName)
        {
            var user = users.SingleOrDefault(x => x.UserName == userName);
            return Task.FromResult(user);
        }

        public Task UpdateAsync(TestUser user)
        {
            return Task.FromResult(0);
        }

        public void Dispose()
        {
        }

        public Task<FailedLoginAttempts> GetFailedLoginAttemptsAsync(TestUser user)
        {
            return Task.FromResult(new FailedLoginAttempts { Count = user.FailedLoginCount, LastFailedDate = user.LastFailedLogin });
        }

        public Task SetFailedLoginAttemptsAsync(TestUser user, FailedLoginAttempts attempts)
        {
            user.FailedLoginCount = attempts.Count;
            user.LastFailedLogin = attempts.LastFailedDate;
            return Task.FromResult(0);
        }

        public Task<string> GetPasswordHashAsync(TestUser user)
        {
            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(TestUser user)
        {
            return Task.FromResult(user.PasswordHash != null);
        }

        public Task SetPasswordHashAsync(TestUser user, string passwordHash)
        {
            user.PasswordHash = passwordHash;
            return Task.FromResult(0);
        }

        public Task<string> GetSecurityStampAsync(TestUser user)
        {
            return Task.FromResult(user.SecurityStamp);
        }

        public Task SetSecurityStampAsync(TestUser user, string stamp)
        {
            user.SecurityStamp = stamp;
            return Task.FromResult(0);
        }

        public Task<string> GetPhoneNumberAsync(TestUser user)
        {
            return Task.FromResult(user.MobilePhone);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(TestUser user)
        {
            return Task.FromResult(user.MobilePhoneConfirmed);
        }

        public Task SetPhoneNumberAsync(TestUser user, string phoneNumber)
        {
            user.MobilePhone = phoneNumber;
            return Task.FromResult(0);
        }

        public Task SetPhoneNumberConfirmedAsync(TestUser user, bool confirmed)
        {
            user.MobilePhoneConfirmed = confirmed;
            return Task.FromResult(0);
        }
    }

    public class TestIdentityRebootUserManager : IdentityRebootUserManager<TestUser>
    {
        public TestIdentityRebootUserManager(IUserStore<TestUser> store, IdentityRebootConfiguration config)
            : base(store, config)
        {
        }

        public DateTime? now;

        protected override DateTime UtcNow
        {
            get
            {
                return now ?? DateTime.UtcNow;
            }
        }
    }

}
