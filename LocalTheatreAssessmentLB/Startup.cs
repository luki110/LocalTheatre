using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(LocalTheatreAssessmentLB.Startup))]
namespace LocalTheatreAssessmentLB
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
