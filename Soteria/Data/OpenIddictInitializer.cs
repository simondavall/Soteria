using OpenIddict.Abstractions;

namespace Soteria.Data;

public sealed class OpenIddictInitializer(IOpenIddictScopeManager scopeManager)
{
    private const string ReferenceApiScope = "reference_api";
    private const string ReferenceApiResource = "reference_api";

    public async Task InitializeAsync(
        CancellationToken cancellationToken = default)
    {
        await EnsureReferenceApiScopeAsync(cancellationToken);
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
}