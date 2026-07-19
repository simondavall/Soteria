using OpenIddict.Abstractions;
using Permissions =
    OpenIddict.Abstractions.OpenIddictConstants.Permissions;

namespace Soteria.Data;

public sealed class OpenIddictInitializer(
    IOpenIddictScopeManager scopeManager,
    IOpenIddictApplicationManager applicationManager,
    IConfiguration configuration)
{
    private const string ReferenceApiScope = "reference_api";
    private const string ReferenceApiResource = "reference_api";

    private const string ReferenceWebClientId = "reference_web";
    private const string ReferenceWebDisplayName = "Reference Web";

    private const string ReferenceWebRedirectUri = "https://localhost:7276/signin-oidc";
    private const string ReferenceWebPostLogoutRedirectUri = "https://localhost:7276/signout-callback-oidc";

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await EnsureReferenceApiScopeAsync(cancellationToken);
        await EnsureReferenceWebApplicationAsync(cancellationToken);
    }

    private async Task EnsureReferenceApiScopeAsync(CancellationToken cancellationToken)
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

    private async Task EnsureReferenceWebApplicationAsync(CancellationToken cancellationToken)
    {
        var application = await applicationManager.FindByClientIdAsync(ReferenceWebClientId, cancellationToken);
        if (application is null)
        {
            await CreateReferenceWebApplicationAsync(cancellationToken);
            return;
        }

        await UpdateReferenceWebApplicationAsync(application, cancellationToken);
    }

    private async Task CreateReferenceWebApplicationAsync(CancellationToken cancellationToken)
    {
        var referenceWebClientSecret =
            configuration["Authentication:OpenIdConnect:ClientSecret"]
            ?? throw new InvalidOperationException(
                "The Authentication:OpenIdConnect:ClientSecret " +
                "configuration value is required.");

        var descriptor = CreateReferenceWebDescriptor();
        descriptor.ClientSecret = referenceWebClientSecret;
        await applicationManager.CreateAsync(descriptor, cancellationToken);
    }

    private async Task UpdateReferenceWebApplicationAsync(object application, CancellationToken cancellationToken)
    {
        var descriptor = new OpenIddictApplicationDescriptor();
        await applicationManager.PopulateAsync(descriptor, application, cancellationToken);

        ApplyReferenceWebConfiguration(descriptor);

        await applicationManager.UpdateAsync(application, descriptor, cancellationToken);
    }

    private static OpenIddictApplicationDescriptor CreateReferenceWebDescriptor()
    {
        var descriptor = new OpenIddictApplicationDescriptor();

        ApplyReferenceWebConfiguration(descriptor);

        return descriptor;
    }

    private static void ApplyReferenceWebConfiguration(OpenIddictApplicationDescriptor descriptor)
    {
        descriptor.ClientId = ReferenceWebClientId;
        descriptor.DisplayName = ReferenceWebDisplayName;
        descriptor.ConsentType = OpenIddictConstants.ConsentTypes.Implicit;
        descriptor.ClientType = OpenIddictConstants.ClientTypes.Confidential;

        descriptor.RedirectUris.Add(new Uri(ReferenceWebRedirectUri));

        descriptor.PostLogoutRedirectUris.Add(new Uri(ReferenceWebPostLogoutRedirectUri));

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