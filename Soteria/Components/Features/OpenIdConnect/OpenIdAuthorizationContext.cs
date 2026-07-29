using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using Soteria.Data;
using Soteria.Data.Authorization;
using Soteria.Data.OpenIddict;

namespace Soteria.Components.Features.OpenIdConnect;

public interface IOpenIdConnectAuthorizationContext
{
    Task<OpenIdConnectAuthorizationResolution> GetAsync(CancellationToken cancellationToken = default);
}

public sealed record ResolvedOpenIdConnectAuthorizationContext(
    SoteriaApplication Application,
    ApplicationUser User,
    ClientMembership? ClientMembership,
    IReadOnlyList<string> ApplicationRoleNames);

public sealed record OpenIdConnectAuthorizationResolution(ResolvedOpenIdConnectAuthorizationContext? Context, OpenIdConnectAuthorizationResolutionFailure Failure)
{
    public bool IsSuccessful => Failure == OpenIdConnectAuthorizationResolutionFailure.None;

    public static OpenIdConnectAuthorizationResolution Success(ResolvedOpenIdConnectAuthorizationContext context)
    {
        return new OpenIdConnectAuthorizationResolution(context, OpenIdConnectAuthorizationResolutionFailure.None);
    }

    public static OpenIdConnectAuthorizationResolution Failed(OpenIdConnectAuthorizationResolutionFailure failure, ResolvedOpenIdConnectAuthorizationContext? context = null)
    {
        return new OpenIdConnectAuthorizationResolution(context, failure);
    }
}

public enum OpenIdConnectAuthorizationResolutionFailure
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

public sealed class OpenIdConnectAuthorizationContext(
    IHttpContextAccessor httpContextAccessor,
    UserManager<ApplicationUser> userManager,
    IOpenIddictApplicationManager applicationManager,
    SoteriaDbContext dbContext)
    : IOpenIdConnectAuthorizationContext
{
    private OpenIdConnectAuthorizationResolution? _resolution;

    public async Task<OpenIdConnectAuthorizationResolution> GetAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_resolution is not null)
        {
            return _resolution;
        }

        var httpContext = httpContextAccessor.HttpContext
            ?? throw new InvalidOperationException("The current HTTP context is unavailable.");

        var authenticationResult = await httpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

        cancellationToken.ThrowIfCancellationRequested();

        if (!authenticationResult.Succeeded || authenticationResult.Principal is null)
        {
            return Cache(
                OpenIdConnectAuthorizationResolution.Failed(
                    OpenIdConnectAuthorizationResolutionFailure.NotAuthenticated));
        }

        var user = await userManager.GetUserAsync(authenticationResult.Principal);

        cancellationToken.ThrowIfCancellationRequested();

        if (user is null)
        {
            return Cache(
                OpenIdConnectAuthorizationResolution.Failed(
                    OpenIdConnectAuthorizationResolutionFailure.IdentityUserNotFound));
        }

        var request = httpContext.GetOpenIddictServerRequest();
        if (request is null)
        {
            return Cache(
                OpenIdConnectAuthorizationResolution.Failed(
                    OpenIdConnectAuthorizationResolutionFailure
                        .AuthorizationRequestUnavailable));
        }

        if (string.IsNullOrWhiteSpace(request.ClientId))
        {
            return Cache(
                OpenIdConnectAuthorizationResolution.Failed(
                    OpenIdConnectAuthorizationResolutionFailure
                        .ClientIdentifierUnavailable));
        }

        var application = await applicationManager.FindByClientIdAsync(request.ClientId, cancellationToken);
        if (application is not SoteriaApplication soteriaApplication)
        {
            return Cache(
                OpenIdConnectAuthorizationResolution.Failed(
                    OpenIdConnectAuthorizationResolutionFailure
                        .ClientApplicationNotFound));
        }

        var applicationIdValue = await applicationManager.GetIdAsync(application, cancellationToken);
        if (!Guid.TryParse(applicationIdValue, out var applicationId))
        {
            return Cache(
                OpenIdConnectAuthorizationResolution.Failed(
                    OpenIdConnectAuthorizationResolutionFailure
                        .ClientApplicationIdentifierInvalid));
        }

        var clientMembership =
            await dbContext.ClientMemberships
                .AsNoTracking()
                .Include(membership => membership.ApplicationRoleAssignments)
                .ThenInclude(assignment => assignment.ApplicationRole)
                .SingleOrDefaultAsync(membership => 
                        membership.UserId == user.Id && 
                        membership.ApplicationId == applicationId,
                    cancellationToken);

        if (clientMembership is null)
        {
            var context =
                new ResolvedOpenIdConnectAuthorizationContext(
                    soteriaApplication,
                    user,
                    ClientMembership: null,
                    ApplicationRoleNames: []);

            return Cache(OpenIdConnectAuthorizationResolution.Failed(OpenIdConnectAuthorizationResolutionFailure.ClientMembershipNotFound, context));
        }

        var applicationRoleNames =
            clientMembership.ApplicationRoleAssignments
                .Where(assignment => assignment.ApplicationId == applicationId && assignment.ApplicationRole.ApplicationId == applicationId)
                .Select(assignment => assignment.ApplicationRole.Name)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(roleName => roleName, StringComparer.Ordinal)
                .ToList();

        return Cache(OpenIdConnectAuthorizationResolution.Success(
            new ResolvedOpenIdConnectAuthorizationContext(
                soteriaApplication,
                user,
                clientMembership,
                applicationRoleNames)));
    }

    private OpenIdConnectAuthorizationResolution Cache(OpenIdConnectAuthorizationResolution resolution)
    {
        _resolution = resolution;
        return resolution;
    }
}