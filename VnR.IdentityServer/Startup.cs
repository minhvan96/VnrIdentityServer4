using IdentityServer4;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using StsServer;
using StsServer.Data;
using StsServer.Models;
using Vnr.IdentityServer.Config;
using Vnr.IdentityServer.Features.Account.Services;
using Vnr.IdentityServer.Features.Account.Services.Interfaces;

namespace Vnr.IdentityServer
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlite(Configuration.GetConnectionString("DefaultConnection")));

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            services.Configure<IISOptions>(iis =>
            {
                iis.AuthenticationDisplayName = "Windows";
                iis.AutomaticAuthentication = true;
            });

            var builder = services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;
            })
                .AddInMemoryIdentityResources(IdentityResourceConfig.IdentityResources)
                .AddInMemoryApiScopes(ApiScopeConfig.ApiScopes)
                .AddInMemoryClients(ClientConfig.Clients)
                .AddAspNetIdentity<ApplicationUser>()
                .AddProfileService<IdentityWithAdditionalClaimsProfileService>();

            services.AddAuthentication()
              .AddGoogle("Google", options =>
              {
                  options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                  options.ClientId = "782231625152-lpjmieqqss3lbsg4gqfh16ks3j5r7osp.apps.googleusercontent.com";
                  options.ClientSecret = "fBxHTyHUk3yjbPmhaQkbRKaO";
              });

            builder.AddDeveloperSigningCredential();

            services.AddScoped<IAccountService, AccountService>();
            services.AddControllersWithViews();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseRouting();

            app.UseIdentityServer();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}