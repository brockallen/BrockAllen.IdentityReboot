using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(VS2013.Startup))]
namespace VS2013
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
