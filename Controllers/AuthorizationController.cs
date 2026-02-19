using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Soteria.Models;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Soteria.Controllers;

public class AuthorizationController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public AuthorizationController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
          throw new InvalidOperationException("OIDC request cannot be retrieved.");

        // If user not logged in → redirect to login
        if (!User.Identity?.IsAuthenticated ?? true) {
            var props = new AuthenticationProperties {
                RedirectUri = Request.Path + QueryString.Create(Request.Query.ToList())
            };

            // tell ASP.NET which scheme to use
            props.Items[".AspNetCore.Authentication.AuthenticationScheme"] = IdentityConstants.ApplicationScheme;

            return Challenge(props);
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return Forbid();

        var principal = await _signInManager.CreateUserPrincipalAsync(user);
        // REQUIRED
        principal.SetClaim(Claims.Subject, user.Id.ToString());

        principal.SetScopes(request.GetScopes());

        foreach (var claim in principal.Claims) {
            claim.SetDestinations(GetDestinations(claim));
        }

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("~/connect/token")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
            throw new InvalidOperationException("The specified grant type is not supported.");

        var result =
            await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme) ??
            throw new Exception("No result");

        var userId = result.Principal!.GetClaim(Claims.Subject);

        if (string.IsNullOrEmpty(userId)) {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?> {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "Cannot find user from the token."
                }));
        }
        var user = await _userManager.FindByIdAsync(userId);
        if (user is null) {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?> {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "User not found"
                }));
        }
     
        var identity = new ClaimsIdentity(result.Principal!.Claims,
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);


        identity.SetClaim(Claims.Subject, userId)
            .SetClaim(Claims.Email, user.Email)
            .SetClaim(Claims.Name, user.UserName)
            .SetClaim(Claims.PreferredUsername, user.DisplayName)
            // todo: Need to add roles allocated to user, but need to be able to allocate roles first.
            .SetClaims(Claims.Role, new List<string> { "ArtemisUser", "Admin" }.ToImmutableArray());

        identity.SetDestinations(GetDestinations);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpGet("~/connect/logout")]
    [HttpPost("~/connect/logout")]
    public async Task<IActionResult> LogoutPost()
    {
        //todo: check that I actually need this sign out.
        await HttpContext.SignOutAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties {
                RedirectUri = "/"
            });
    }

    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        switch (claim.Type) {
            case Claims.Name:
            case Claims.Email:
            case Claims.PreferredUsername:
            case Claims.Role:
                yield return Destinations.AccessToken;
                yield return Destinations.IdentityToken;
                break;

            default:
                yield return Destinations.AccessToken;
                break;
        }
    }
}

