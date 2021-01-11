using IdentityServer4.Models;
using System.Collections.Generic;

namespace Vnr.IdentityServer.Config
{
    public static class ApiScopeConfig
    {
        public static IEnumerable<ApiScope> ApiScopes =>
             new List<ApiScope>
             {
                new ApiScope("scope_used_for_hybrid_flow", "Scope for the scope_used_for_hybrid_flow"),
             };
    }
}