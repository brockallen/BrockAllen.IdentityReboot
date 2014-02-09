using Microsoft.AspNet.Identity;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BrockAllen.IdentityReboot.Tests
{
    [TestClass]
    public class TwoFactorAuthBruteForceTests
    {
        IdentityRebootConfiguration configuration;
        TestIdentityRebootUserManager subject;
        TestUserStore store;
        TestUser user;

        const string username = "test";
        const string password = "pass123";
        const string provider = "mobile";

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
            subject.RegisterTwoFactorProvider(provider, new PhoneNumberTokenProvider<TestUser>
            {
                MessageFormat = "Your security code is: {0}"
            });

            user = new TestUser(){
                UserName = username
            };
            var result = subject.Create(user, password);
            Assert.IsTrue(result.Succeeded);
        }

        [TestMethod]
        public void CorrectCode_NoFailedAttempts()
        {
            var acct = subject.Find(username, password);
            var token = subject.GenerateTwoFactorToken(user.Id, provider);
            var result = subject.VerifyTwoFactorToken(user.Id, provider, token);
            
            Assert.IsTrue(result);
            Assert.AreEqual(0, user.FailedLoginCount);
            Assert.IsNull(user.LastFailedLogin);
        }

        [TestMethod]
        public void InvalidCode_RecordFailedLoginAttempts()
        {
            var now = new DateTime(2000, 2, 3);
            subject.now = now;

            var acct = subject.Find(username, password);
            Assert.IsNotNull(acct);
            var token = subject.GenerateTwoFactorToken(user.Id, provider);
            var result = subject.VerifyTwoFactorToken(user.Id, provider, "abc");
            Assert.IsFalse(result);
            Assert.AreEqual(1, user.FailedLoginCount);
            Assert.AreEqual(now, user.LastFailedLogin);

            result = subject.VerifyTwoFactorToken(user.Id, provider, "abc");
            Assert.IsFalse(result);
            result = subject.VerifyTwoFactorToken(user.Id, provider, "abc");
            Assert.IsFalse(result);
            
            Assert.AreEqual(3, user.FailedLoginCount);
            Assert.AreEqual(now, user.LastFailedLogin);
        }

        [TestMethod]
        public void AfterMaxAttempts_AccountLockedOut()
        {
            subject.now = new DateTime(2000, 2, 3);
            
            var acct = subject.Find(username, password);
            Assert.IsNotNull(acct);
            var token = subject.GenerateTwoFactorToken(user.Id, provider);
            for (var i = 0; i < configuration.FailedLoginsAllowed; i++)
            {
                Assert.IsFalse(subject.VerifyTwoFactorToken(user.Id, provider, "abc"));
            }
            
            Assert.IsFalse(subject.VerifyTwoFactorToken(user.Id, provider, token));
        }

        [TestMethod]
        public void AfterLockoutDuration_UserCanLogin()
        {
            var acct = subject.Find(username, password);
            Assert.IsNotNull(acct);

            user.FailedLoginCount = configuration.FailedLoginsAllowed;
            user.LastFailedLogin = new DateTime(2000, 2, 3);
            subject.now = user.LastFailedLogin;

            var token = subject.GenerateTwoFactorToken(user.Id, provider);
            Assert.IsFalse(subject.VerifyTwoFactorToken(user.Id, provider, token));

            subject.now = user.LastFailedLogin + configuration.FailedLoginLockout;
            token = subject.GenerateTwoFactorToken(user.Id, provider);
            Assert.IsTrue(subject.VerifyTwoFactorToken(user.Id, provider, token));
        }

        [TestMethod]
        public void AfterLockoutDuration_CountIsReset()
        {
            var acct = subject.Find(username, password);
            Assert.IsNotNull(acct);

            user.FailedLoginCount = configuration.FailedLoginsAllowed;
            user.LastFailedLogin = new DateTime(2000, 2, 3);
            subject.now = user.LastFailedLogin + configuration.FailedLoginLockout;

            var token = subject.GenerateTwoFactorToken(user.Id, provider);
            Assert.IsFalse(subject.VerifyTwoFactorToken(user.Id, provider, "abc"));
            
            Assert.AreEqual(1, user.FailedLoginCount);
            Assert.AreEqual(subject.now, user.LastFailedLogin);
        }
    }
}
