using IdentityServer4;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
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
              })
              .AddOpenIdConnect("aad", "Azure AD", options =>
              {
                  options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                  options.SignOutScheme = IdentityServerConstants.SignoutScheme;

                  options.Authority = "https://login.windows.net/4bfa8b1e-02a9-4a13-b7fa-274e458c4897";
                  options.ClientId = "9390f01c-6cb2-41ba-a638-b951d367a82d";
                  options.ResponseType = OpenIdConnectResponseType.IdToken;
                  options.CallbackPath = "/signin-aad";
                  options.SignedOutCallbackPath = "/signout-callback-aad";
                  options.RemoteSignOutPath = "/signout-aad";
                  options.TokenValidationParameters = new TokenValidationParameters
                  {
                      NameClaimType = "name",
                      RoleClaimType = "role"
                  };
              }); ;

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