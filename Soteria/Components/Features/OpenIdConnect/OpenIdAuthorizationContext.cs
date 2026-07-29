using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using Soteria.Data;
using Soteria.Data.Authorization;
using Soteria.Data.OpenIddict;

namespace Soteria.Components.Features.OpenIdConnect;

public interface IOpenIdAuthorizationContext
{
    Task<OpenIdAuthorizationResolution> GetAsync(CancellationToken cancellationToken = default);
}

public sealed record ResolvedOpenIdAuthorizationContext(
    SoteriaApplication Application,
    ApplicationUser User,
    ClientMembership? ClientMembership,
    IReadOnlyList<string> ApplicationRoleNames);

public sealed record OpenIdAuthorizationResolution(ResolvedOpenIdAuthorizationContext? Context, OpenIdAuthorizationResolutionFailure Failure)
{
    public bool IsSuccessful => Failure == OpenIdAuthorizationResolutionFailure.None;

    public static OpenIdAuthorizationResolution Success(ResolvedOpenIdAuthorizationContext context)
    {
        return new OpenIdAuthorizationResolution(context, OpenIdAuthorizationResolutionFailure.None);
    }

    public static OpenIdAuthorizationResolution Failed(OpenIdAuthorizationResolutionFailure failure, ResolvedOpenIdAuthorizationContext? context = null)
    {
        return new OpenIdAuthorizationResolution(context, failure);
    }
}

public enum OpenIdAuthorizationResolutionFailure
{
    None,
    NotAuthenticated,
    AuthorizationRequestUnavailable,
    ClientIdentifierUnavailable,
    ClientApplicationNotFound,
    ClientApplicationIdentifierInvalid,
    IdentityUserNotFound,
    ClientMembershipNotFound
}

public sealed class OpenIdAuthorizationContext(
    IHttpContextAccessor httpContextAccessor,
    UserManager<ApplicationUser> userManager,
    IOpenIdClientMembershipResolver clientMembershipResolver)
    : IOpenIdAuthorizationContext
{
    private OpenIdAuthorizationResolution? _resolution;

    public async Task<OpenIdAuthorizationResolution> GetAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_resolution is not null)
        {
            return _resolution;
        }

        var httpContext = httpContextAccessor.HttpContext
                          ?? throw new InvalidOperationException(
                              "The current HTTP context is unavailable.");
        
        var authenticationResult = await httpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

        cancellationToken.ThrowIfCancellationRequested();

        if (!authenticationResult.Succeeded || authenticationResult.Principal is null)
        {
            return Cache(OpenIdAuthorizationResolution.Failed(OpenIdAuthorizationResolutionFailure.NotAuthenticated));
        }

        var user = await userManager.GetUserAsync(authenticationResult.Principal);

        cancellationToken.ThrowIfCancellationRequested();

        if (user is null)
        {
            return Cache(OpenIdAuthorizationResolution.Failed(OpenIdAuthorizationResolutionFailure.IdentityUserNotFound));
        }

        var request = httpContext.GetOpenIddictServerRequest();

        if (request is null)
        {
            return Cache(OpenIdAuthorizationResolution.Failed(OpenIdAuthorizationResolutionFailure.AuthorizationRequestUnavailable));
        }

        var resolution = await clientMembershipResolver.ResolveAsync(request.ClientId, user.Id.ToString(), cancellationToken);

        return Cache(resolution);
    }

    private OpenIdAuthorizationResolution Cache(OpenIdAuthorizationResolution resolution)
    {
        _resolution = resolution;
        return resolution;
    }
}