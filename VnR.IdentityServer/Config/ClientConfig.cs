using IdentityServer4.Models;
using System.Collections.Generic;

namespace Vnr.IdentityServer.Config
{
    public static class ClientConfig
    {
        public static IEnumerable<Client> Clients =>
            new List<Client>
            {
                 new Client
                 {
                    ClientId = "hybridclient",
                    ClientName = "MVC Client",

                    AllowedGrantTypes = GrantTypes.HybridAndClientCredentials,
                    ClientSecrets = { new Secret("hybrid_flow_secret".Sha256()) },
                    RequirePkce = false,
                    RedirectUris = { "https://localhost:44381/signin-oidc" },
                    FrontChannelLogoutUri = "https://localhost:44381/signout-oidc",
                    PostLogoutRedirectUris = { "https://localhost:44381/signout-callback-oidc" },

                    AllowOfflineAccess = true,
                    //AlwaysIncludeUserClaimsInIdToken = true,
                    AllowedScopes = { "openid", "profile", "offline_access" }
                 }
            };
    }
}