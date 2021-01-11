using IdentityModel;
using IdentityServer4;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using StsServer.Models;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Vnr.IdentityServer.Features.Account.Services.Interfaces;

namespace Vnr.IdentityServer.Quickstart.Account.Controllers
{
    public class WindowsAccountController : Controller
    {
        private readonly IIdentityServerInteractionService _interaction;
        private readonly ILogger<WindowsAccountController> _logger;
        private readonly IEventService _events;
        private readonly IAccountService _accountService;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public WindowsAccountController(
            IIdentityServerInteractionService interaction,
            IEventService events,
            ILogger<WindowsAccountController> logger,
            IAccountService accountService,
            SignInManager<ApplicationUser> signInManager
            )
        {
            // if the TestUserStore is not in DI, then we'll just use the global users collection
            // this is where you would plug in your own custom identity management library (e.g. ASP.NET Identity)

            _interaction = interaction;
            _logger = logger;
            _events = events;
            _accountService = accountService;
            _signInManager = signInManager;
        }

        [HttpGet]
        public async Task<IActionResult> Callback()
        {
            // read external identity from the temporary cookie
            var result = await HttpContext.AuthenticateAsync(IdentityConstants.ExternalScheme);
            if (result?.Succeeded != true)
            {
                throw new Exception("External authentication error");
            }

            // lookup our user and external provider info
            var (user, provider, providerUserId, claims) = await _accountService.FindUserFromExternalProviderAsync(result);
            if (user == null)
            {
                // this might be where you might initiate a custom workflow for user registration
                // in this sample we don't show how that would be done, as our sample implementation
                // simply auto-provisions new external user
                user = await _accountService.AutoProvisionUserAsync(provider, providerUserId, claims);
            }

            // this allows us to collect any additonal claims or properties
            // for the specific prtotocols used and store them in the local auth cookie.
            // this is typically used to store data needed for signout from those protocols.
            var additionalLocalClaims = new List<Claim>();
            additionalLocalClaims.AddRange(claims);

            var localSignInProps = new AuthenticationProperties();
            _accountService.ProcessLoginCallbackForOidc(result, additionalLocalClaims, localSignInProps);
            _accountService.ProcessLoginCallbackForWsFed(result, additionalLocalClaims, localSignInProps);
            _accountService.ProcessLoginCallbackForSaml2p(result, additionalLocalClaims, localSignInProps);

            // issue authentication cookie for user
            // we must issue the cookie maually, and can't use the SignInManager because
            // it doesn't expose an API to issue additional claims from the login workflow
            var principal = await _signInManager.CreateUserPrincipalAsync(user);
            additionalLocalClaims.AddRange(principal.Claims);

            var name = principal.FindFirst(JwtClaimTypes.Name)?.Value ?? user.Id;
            await _events.RaiseAsync(new UserLoginSuccessEvent(provider, providerUserId, user.Id, name));

            // issue authentication cookie for user
            var isuser = new IdentityServerUser(principal.GetSubjectId())
            {
                DisplayName = name,
                IdentityProvider = provider,
                AdditionalClaims = additionalLocalClaims
            };

            await HttpContext.SignInAsync(isuser, localSignInProps);

            // delete temporary cookie used during external authentication
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            // validate return URL and redirect back to authorization endpoint or a local page
            var returnUrl = result.Properties.Items["returnUrl"];
            if (_interaction.IsValidReturnUrl(returnUrl) || Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            return Redirect("~/");
        }
    }
}