using OpenIddict.Abstractions;
using Permissions = OpenIddict.Abstractions.OpenIddictConstants.Permissions;

namespace Soteria.Data;

public sealed class OpenIddictInitializer(IOpenIddictScopeManager scopeManager, IOpenIddictApplicationManager applicationManager, IConfiguration configuration)
{
    private const string ReferenceApiScope = "reference_api";
    private const string ReferenceApiResource = "reference_api";
    
    private const string ReferenceWebClientId = "reference_web";
    private const string ReferenceWebDisplayName = "Reference Web";
    private const string ReferenceWebRedirectUri = "https://localhost:7276/signin-oidc";

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await EnsureReferenceApiScopeAsync(cancellationToken);
        await EnsureReferenceWebApplicationAsync(cancellationToken);
    }

    private async Task EnsureReferenceApiScopeAsync(
        CancellationToken cancellationToken)
    {
        var scope = await scopeManager.FindByNameAsync(ReferenceApiScope, cancellationToken);
        if (scope is not null)
        {
            return;
        }

        var descriptor = new OpenIddictScopeDescriptor
        {
            Name = ReferenceApiScope,
            DisplayName = "Reference API"
        };

        descriptor.Resources.Add(ReferenceApiResource);

        await scopeManager.CreateAsync(descriptor, cancellationToken);
    }
    
    private async Task EnsureReferenceWebApplicationAsync(
        CancellationToken cancellationToken)
    {
        var application =
            await applicationManager.FindByClientIdAsync(
                ReferenceWebClientId,
                cancellationToken);

        if (application is not null)
        {
            return;
        }

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = ReferenceWebClientId,
            DisplayName = ReferenceWebDisplayName,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ClientSecret = configuration["ReferenceWeb:ClientSecret"]
        };

        descriptor.RedirectUris.Add(new Uri(ReferenceWebRedirectUri));

        descriptor.Permissions.UnionWith(
        [
            Permissions.Endpoints.Authorization,
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

        await applicationManager.CreateAsync(descriptor, cancellationToken);
    }
}