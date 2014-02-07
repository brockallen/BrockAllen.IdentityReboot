using BrockAllen.IdentityReboot;
using BrockAllen.IdentityReboot.Ef;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System;

namespace VS2013.Models
{
    // You can add profile data for the user by adding more properties to your ApplicationUser class, please visit http://go.microsoft.com/fwlink/?LinkID=317594 to learn more.
    public class ApplicationUser : IdentityUser, IPasswordBruteForcePrevention
    {
        public virtual int FailedLoginCount { get; set; }
        public virtual DateTime? LastFailedLogin { get; set; }
    }

    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext()
            : base("DefaultConnection")
        {
        }
    }

    public class ApplicationUserManager : IdentityRebootUserManager<ApplicationUser>
    {
        public ApplicationUserManager()
            : base(new IdentityRebootUserStore<ApplicationUser>(new ApplicationDbContext()))
        {
            //this.PasswordHasher = new AdaptivePasswordHasher();
        }
    }
}