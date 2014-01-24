using Microsoft.AspNet.Identity;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace BrockAllen.IdentityReboot.Tests
{
    [TestClass]
    public class AdaptivePasswordHasherTests
    {
        TestAdaptivePasswordHasher subject;

        [TestInitialize]
        public void Init()
        {
            subject = new TestAdaptivePasswordHasher();
            subject.CurrentYear = CurrentYear;
        }

        const int IterationsForCurrentYear = 64000;
        const int CurrentYear = 2012;

        [TestMethod]
        public void HashPassword_CountStoredInHashedPassword()
        {
            {
                var result = subject.HashPassword("pass");
                StringAssert.StartsWith(result, subject.EncodeIterations(IterationsForCurrentYear) + AdaptivePasswordHasher.PasswordHashingIterationCountSeparator);
            }
            {
                subject.IterationCount = 5000;
                var result = subject.HashPassword("pass");
                StringAssert.StartsWith(result, subject.EncodeIterations(5000) + AdaptivePasswordHasher.PasswordHashingIterationCountSeparator);
            }
            {
                subject.IterationCount = 10000;
                var result = subject.HashPassword("pass");
                StringAssert.StartsWith(result, subject.EncodeIterations(10000) + AdaptivePasswordHasher.PasswordHashingIterationCountSeparator);
            }
            {
                subject.IterationCount = 50;
                var result = subject.HashPassword("pass");
                StringAssert.StartsWith(result, subject.EncodeIterations(50) + AdaptivePasswordHasher.PasswordHashingIterationCountSeparator);
            }
        }

        [TestMethod]
        public void NegativeCount_UsesCurrentYearPrefix()
        {
            subject.IterationCount = -1;
            var result = subject.HashPassword("pass");
            StringAssert.StartsWith(result, subject.EncodeIterations(IterationsForCurrentYear) + AdaptivePasswordHasher.PasswordHashingIterationCountSeparator);
        }

        [TestMethod]
        public void ZeroCount_UsesCurrentYearPrefix()
        {
            subject.IterationCount = 0;
            var result = subject.HashPassword("pass");
            StringAssert.StartsWith(result, subject.EncodeIterations(IterationsForCurrentYear) + AdaptivePasswordHasher.PasswordHashingIterationCountSeparator);
        }

        [TestMethod]
        public void HashedPassword_Verifies()
        {
            subject.IterationCount = 5000;
            var hash = subject.HashPassword("pass");
            Assert.IsTrue(subject.VerifyHashedPassword(hash, "pass")==Microsoft.AspNet.Identity.PasswordVerificationResult.Success);
        }

        [TestMethod]
        public void IncorrectPassword_DoesNotVerify()
        {
            subject.IterationCount = 5000;
            var hash = subject.HashPassword("pass1");
            Assert.IsFalse(subject.VerifyHashedPassword(hash, "pass2") == Microsoft.AspNet.Identity.PasswordVerificationResult.Success);
        }
        
        [TestMethod]
        public void PasswordHashingIterationCountChangedAfterHash_StillVerifies()
        {
            subject.IterationCount = 5000;
            var hash = subject.HashPassword("pass");
            Assert.IsTrue(subject.VerifyHashedPassword(hash, "pass") == Microsoft.AspNet.Identity.PasswordVerificationResult.Success);
        }

        [TestMethod]
        public void PasswordWithoutPrefix_StillValidatesWithDefault()
        {
            var hash = subject.HashPassword("pass");
            Assert.IsTrue(subject.VerifyHashedPassword(hash, "pass") == Microsoft.AspNet.Identity.PasswordVerificationResult.Success);
        }

        [TestMethod]
        public void IncorrectPrefix_DoesNotVerify()
        {
            {
                var hash = subject.HashPassword("pass");
                Assert.IsFalse(subject.VerifyHashedPassword(subject.EncodeIterations(5000) + "." + hash, "pass") == Microsoft.AspNet.Identity.PasswordVerificationResult.Success);
            }
            {
                var hash = subject.HashPassword("pass");
                Assert.IsFalse(subject.VerifyHashedPassword(subject.EncodeIterations(5000) + ".5." + hash, "pass") == Microsoft.AspNet.Identity.PasswordVerificationResult.Success);
            }
            {
                var hash = subject.HashPassword("pass");
                Assert.IsFalse(subject.VerifyHashedPassword("hello." + hash, "pass") == Microsoft.AspNet.Identity.PasswordVerificationResult.Success);
            }
            {
                var hash = subject.HashPassword("pass");
                Assert.IsFalse(subject.VerifyHashedPassword("-1." + hash, "pass") == Microsoft.AspNet.Identity.PasswordVerificationResult.Success);
            }
            {
                subject.IterationCount = 10000;
                var hash = subject.HashPassword("pass");
                hash = hash.Replace(subject.EncodeIterations(10000), subject.EncodeIterations(5000));
                Assert.IsFalse(subject.VerifyHashedPassword(hash, "pass") == Microsoft.AspNet.Identity.PasswordVerificationResult.Success);
            }
        }

        [TestMethod]
        public void GetIterationsFromYear_CalculatesCorrectValues()
        {
            Assert.AreEqual(1000, subject.GetIterationsFromYear(-1));
            Assert.AreEqual(1000, subject.GetIterationsFromYear(1999));
            Assert.AreEqual(1000, subject.GetIterationsFromYear(2000));
            Assert.AreEqual(1000, subject.GetIterationsFromYear(2001));

            Assert.AreEqual(2000, subject.GetIterationsFromYear(2002));
            Assert.AreEqual(2000, subject.GetIterationsFromYear(2003));

            Assert.AreEqual(4000, subject.GetIterationsFromYear(2004));

            Assert.AreEqual(8000, subject.GetIterationsFromYear(2006));

            Assert.AreEqual(16000, subject.GetIterationsFromYear(2008));

            Assert.AreEqual(32000, subject.GetIterationsFromYear(2010));

            Assert.AreEqual(64000, subject.GetIterationsFromYear(2012));

            Assert.AreEqual(2097152000, subject.GetIterationsFromYear(2042));

            Assert.AreEqual(Int32.MaxValue, subject.GetIterationsFromYear(2044));
            Assert.AreEqual(Int32.MaxValue, subject.GetIterationsFromYear(2045));
            Assert.AreEqual(Int32.MaxValue, subject.GetIterationsFromYear(2046));
        }

        [TestMethod]
        public void VerifyHashedPassword_HashFromDefaultPasswordHasher_Works()
        {
            var ph = new PasswordHasher();
            var hash = ph.HashPassword("pass");
            Assert.IsTrue(subject.VerifyHashedPassword(hash, "pass") == PasswordVerificationResult.Success);
        }
    }

    public class TestAdaptivePasswordHasher : AdaptivePasswordHasher
    {
        public int CurrentYear { get; set; }

        public override int GetCurrentYear()
        {
            return CurrentYear;
        }
    }
}
