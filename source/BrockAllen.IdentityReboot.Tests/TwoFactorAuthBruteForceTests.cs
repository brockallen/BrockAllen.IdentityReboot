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
    public class TwoFactorAuthBruteForceTests : IdentityRebootTestBase
    {
        const string provider = "mobile";

        [TestInitialize]
        public override void Init()
        {
            base.Init();
            manager.RegisterTwoFactorProvider(provider, new PhoneNumberTokenProvider<TestUser>
            {
                MessageFormat = "Your security code is: {0}"
            });
        }

        [TestMethod]
        public void CorrectCode_NoFailedAttempts()
        {
            var acct = manager.Find(username, password);
            var token = manager.GenerateTwoFactorToken(user.Id, provider);
            var result = manager.VerifyTwoFactorToken(user.Id, provider, token);
            
            Assert.IsTrue(result);
            Assert.AreEqual(0, user.FailedLoginCount);
            Assert.IsNull(user.LastFailedLogin);
        }

        [TestMethod]
        public void InvalidCode_RecordFailedLoginAttempts()
        {
            var now = new DateTime(2000, 2, 3);
            manager.now = now;

            var acct = manager.Find(username, password);
            Assert.IsNotNull(acct);
            var token = manager.GenerateTwoFactorToken(user.Id, provider);
            var result = manager.VerifyTwoFactorToken(user.Id, provider, "abc");
            Assert.IsFalse(result);
            Assert.AreEqual(1, user.FailedLoginCount);
            Assert.AreEqual(now, user.LastFailedLogin);

            result = manager.VerifyTwoFactorToken(user.Id, provider, "abc");
            Assert.IsFalse(result);
            result = manager.VerifyTwoFactorToken(user.Id, provider, "abc");
            Assert.IsFalse(result);
            
            Assert.AreEqual(3, user.FailedLoginCount);
            Assert.AreEqual(now, user.LastFailedLogin);
        }

        [TestMethod]
        public void AfterMaxAttempts_AccountLockedOut()
        {
            manager.now = new DateTime(2000, 2, 3);
            
            var acct = manager.Find(username, password);
            Assert.IsNotNull(acct);
            var token = manager.GenerateTwoFactorToken(user.Id, provider);
            for (var i = 0; i < configuration.FailedLoginsAllowed; i++)
            {
                Assert.IsFalse(manager.VerifyTwoFactorToken(user.Id, provider, "abc"));
            }
            
            Assert.IsFalse(manager.VerifyTwoFactorToken(user.Id, provider, token));
        }

        [TestMethod]
        public void AfterLockoutDuration_UserCanLogin()
        {
            var acct = manager.Find(username, password);
            Assert.IsNotNull(acct);

            user.FailedLoginCount = configuration.FailedLoginsAllowed;
            user.LastFailedLogin = new DateTime(2000, 2, 3);
            manager.now = user.LastFailedLogin;

            var token = manager.GenerateTwoFactorToken(user.Id, provider);
            Assert.IsFalse(manager.VerifyTwoFactorToken(user.Id, provider, token));

            manager.now = user.LastFailedLogin + configuration.FailedLoginLockout;
            token = manager.GenerateTwoFactorToken(user.Id, provider);
            Assert.IsTrue(manager.VerifyTwoFactorToken(user.Id, provider, token));
        }

        [TestMethod]
        public void AfterLockoutDuration_CountIsReset()
        {
            var acct = manager.Find(username, password);
            Assert.IsNotNull(acct);

            user.FailedLoginCount = configuration.FailedLoginsAllowed;
            user.LastFailedLogin = new DateTime(2000, 2, 3);
            manager.now = user.LastFailedLogin + configuration.FailedLoginLockout;

            var token = manager.GenerateTwoFactorToken(user.Id, provider);
            Assert.IsFalse(manager.VerifyTwoFactorToken(user.Id, provider, "abc"));
            
            Assert.AreEqual(1, user.FailedLoginCount);
            Assert.AreEqual(manager.now, user.LastFailedLogin);
        }
    }
}
