using IdentityServer4.Models;
using System.Collections.Generic;

namespace Vnr.IdentityServer.Config
{
    public static class IdentityResourceConfig
    {
        public static IEnumerable<IdentityResource> IdentityResources =>
            new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email()
            };
    }
}