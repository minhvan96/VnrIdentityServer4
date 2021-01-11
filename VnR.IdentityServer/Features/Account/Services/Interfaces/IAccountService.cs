using Microsoft.AspNetCore.Authentication;
using StsServer.Models;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Vnr.IdentityServer.Features.Account.Services.Interfaces
{
    public interface IAccountService
    {
        Task<ApplicationUser> AutoProvisionUserAsync(string provider, string providerUserId, IEnumerable<Claim> claims);

        Task<(ApplicationUser user, string provider, string providerUserId, IEnumerable<Claim> claims)> FindUserFromExternalProviderAsync(AuthenticateResult result);

        void ProcessLoginCallbackForOidc(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps);

        void ProcessLoginCallbackForWsFed(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps);

        void ProcessLoginCallbackForSaml2p(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps);
    }
}