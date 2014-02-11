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
    public class PasswordBruteForceTests : IdentityRebootTestBase
    {
        [TestMethod]
        public void CorrectCredentials_NoFailedLoginAttempts()
        {
            var acct = manager.Find(username, password);
            Assert.AreEqual(0, acct.FailedLoginCount);
            Assert.IsNull(acct.LastFailedLogin);
        }
        
        [TestMethod]
        public void InvalidCredentials_RecordFailedLoginAttempts()
        {
            var now = new DateTime(2000, 2, 3);
            manager.now = now;

            var acct = manager.Find(username, "foo");
            Assert.IsNull(acct);
            Assert.AreEqual(1, user.FailedLoginCount);
            Assert.AreEqual(now, user.LastFailedLogin);

            manager.Find(username, "foo");
            manager.Find(username, "foo");
            Assert.IsNull(acct);
            Assert.AreEqual(3, user.FailedLoginCount);
            Assert.AreEqual(now, user.LastFailedLogin);
        }

        [TestMethod]
        public void AfterMaxAttempts_AccountLockedOut()
        {
            var acct = manager.Find(username, password);
            Assert.IsNotNull(acct);
            for (var i = 0; i < configuration.FailedLoginsAllowed; i++)
            {
                manager.Find(username, "foo");
            }
            acct = manager.Find(username, password);
            Assert.IsNull(acct);
        }

        [TestMethod]
        public void AfterLockoutDuration_UserCanLogin()
        {
            user.FailedLoginCount = configuration.FailedLoginsAllowed;
            user.LastFailedLogin = new DateTime(2000, 2, 3);
            manager.now = user.LastFailedLogin;

            var acct = manager.Find(username, password);
            Assert.IsNull(acct);

            manager.now = user.LastFailedLogin + configuration.FailedLoginLockout;
            acct = manager.Find(username, password);
            Assert.IsNotNull(acct);
        }
        
        [TestMethod]
        public void AfterLockoutDuration_CountIsReset()
        {
            user.FailedLoginCount = configuration.FailedLoginsAllowed;
            user.LastFailedLogin = new DateTime(2000, 2, 3);
            manager.now = user.LastFailedLogin + configuration.FailedLoginLockout;

            var acct = manager.Find(username, "foo");
            Assert.AreEqual(1, user.FailedLoginCount);
            Assert.AreEqual(manager.now, user.LastFailedLogin);
        }
    }
}
