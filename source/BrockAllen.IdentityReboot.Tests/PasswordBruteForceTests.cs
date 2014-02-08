using Microsoft.AspNet.Identity;
using Microsoft.VisualStudio.TestTools.UnitTesting;
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
        public int FailedLoginCount { get; set; }
        public DateTime? LastFailedLogin { get; set; }
    }

    public class TestUserStore : IUserStore<TestUser>, IUserPasswordStore<TestUser>, IPasswordBruteForcePreventionStore<TestUser, string>
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
            return Task.FromResult(new FailedLoginAttempts { Count = user.FailedLoginCount, LastFailedDate = user.LastFailedLogin});
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

    [TestClass]
    public class PasswordBruteForceTests
    {
        IdentityRebootConfiguration configuration;
        TestIdentityRebootUserManager subject;
        TestUserStore store;
        TestUser user;

        const string username = "test";
        const string password = "pass123";

        [TestInitialize]
        public void Init()
        {
            store = new TestUserStore();
            configuration = new IdentityRebootConfiguration()
            {
                FailedLoginsAllowed = 5, 
                PasswordHashIterations = 100, 
                FailedLoginLockout = TimeSpan.FromMinutes(5)
            };
            subject = new TestIdentityRebootUserManager(store, configuration);

            user = new TestUser(){
                UserName = username
            };
            var result = subject.Create(user, password);
            Assert.IsTrue(result.Succeeded);
        }

        [TestMethod]
        public void CorrectCredentials_NoFailedLoginAttempts()
        {
            var acct = subject.Find(username, password);
            Assert.AreEqual(0, acct.FailedLoginCount);
            Assert.IsNull(acct.LastFailedLogin);
        }
        
        [TestMethod]
        public void InvalidCredentials_RecordFailedLoginAttempts()
        {
            var now = new DateTime(2000, 2, 3);
            subject.now = now;
            
            var acct = subject.Find(username, "foo");
            Assert.IsNull(acct);
            Assert.AreEqual(1, user.FailedLoginCount);
            Assert.AreEqual(now, user.LastFailedLogin);

            subject.Find(username, "foo");
            subject.Find(username, "foo");
            Assert.IsNull(acct);
            Assert.AreEqual(3, user.FailedLoginCount);
            Assert.AreEqual(now, user.LastFailedLogin);
        }

        [TestMethod]
        public void AfterMaxAttempts_AccountLockedOut()
        {
            var acct = subject.Find(username, password);
            Assert.IsNotNull(acct);
            for (var i = 0; i < configuration.FailedLoginsAllowed; i++)
            {
                subject.Find(username, "foo");
            }
            acct = subject.Find(username, password);
            Assert.IsNull(acct);
        }

        [TestMethod]
        public void AfterLockoutDuration_UserCanLogin()
        {
            user.FailedLoginCount = configuration.FailedLoginsAllowed;
            user.LastFailedLogin = new DateTime(2000, 2, 3);
            subject.now = user.LastFailedLogin;

            var acct = subject.Find(username, password);
            Assert.IsNull(acct);

            subject.now = user.LastFailedLogin + configuration.FailedLoginLockout;
            acct = subject.Find(username, password);
            Assert.IsNotNull(acct);
        }
        
        [TestMethod]
        public void AfterLockoutDuration_CountIsReset()
        {
            user.FailedLoginCount = configuration.FailedLoginsAllowed;
            user.LastFailedLogin = new DateTime(2000, 2, 3);
            subject.now = user.LastFailedLogin + configuration.FailedLoginLockout;

            var acct = subject.Find(username, "foo");
            Assert.AreEqual(1, user.FailedLoginCount);
            Assert.AreEqual(subject.now, user.LastFailedLogin);
        }
    }
}
