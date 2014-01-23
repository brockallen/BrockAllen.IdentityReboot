using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(PasswordHasher.Startup))]
namespace PasswordHasher
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
