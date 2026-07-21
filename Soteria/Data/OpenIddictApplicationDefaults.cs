using OpenIddict.Abstractions;
using Permissions = OpenIddict.Abstractions.OpenIddictConstants.Permissions;

namespace Soteria.Data;

internal static class OpenIddictApplicationDefaults
{
    public const string ReferenceApiScope = "reference_api";

    public const string ReferenceApiResource = "reference_api";

    public static void Apply(OpenIddictApplicationDescriptor descriptor)
    {
        descriptor.ClientType = OpenIddictConstants.ClientTypes.Confidential;
        descriptor.ConsentType = OpenIddictConstants.ConsentTypes.Implicit;

        descriptor.Permissions.UnionWith(
        [
            Permissions.Endpoints.Authorization,
            Permissions.Endpoints.EndSession,
            Permissions.Endpoints.Token,

            Permissions.GrantTypes.AuthorizationCode,
            Permissions.GrantTypes.RefreshToken,

            Permissions.ResponseTypes.Code,

            Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OpenId,
            Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.Profile,
            Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.Email,
            Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OfflineAccess,
            Permissions.Prefixes.Scope + ReferenceApiScope
        ]);

        descriptor.Requirements.Add(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
    }
}