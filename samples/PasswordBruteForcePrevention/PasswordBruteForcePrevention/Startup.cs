using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(PasswordBruteForcePrevention.Startup))]
namespace PasswordBruteForcePrevention
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
