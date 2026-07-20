using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Soteria.Data;

namespace Soteria.Components.Features.Clients;

public sealed class ClientService
{
    private readonly SoteriaDbContext _dbContext;

    public ClientService(SoteriaDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<IReadOnlyList<ClientSummary>> GetClientsAsync(
        CancellationToken cancellationToken = default)
    {
        return await _dbContext
            .Set<OpenIddictEntityFrameworkCoreApplication<Guid>>()
            .AsNoTracking()
            .Where(application => application.ClientId != null)
            .OrderBy(application =>
                application.DisplayName ?? application.ClientId)
            .Select(application => new ClientSummary(
                application.ClientId!,
                application.DisplayName ?? application.ClientId!,
                application.ClientType ?? string.Empty,
                application.ConsentType ?? string.Empty))
            .ToListAsync(cancellationToken);
    }

    public async Task<ClientApplicationDetails?> GetClientAsync(
        string clientId,
        CancellationToken cancellationToken = default)
    {
        var application = await _dbContext
            .Set<OpenIddictEntityFrameworkCoreApplication<Guid>>()
            .AsNoTracking()
            .Where(application => application.ClientId == clientId)
            .Select(application => new
            {
                application.ClientId,
                application.DisplayName,
                application.ClientType,
                application.ConsentType,
                application.Permissions,
                application.RedirectUris,
                application.PostLogoutRedirectUris
            })
            .SingleOrDefaultAsync(cancellationToken);

        if (application is null)
        {
            return null;
        }

        var permissions = DeserializeStringArray(application.Permissions);

        return new ClientApplicationDetails(
            application.ClientId ?? clientId,
            application.DisplayName ?? application.ClientId ?? clientId,
            application.ClientType ?? string.Empty,
            application.ConsentType ?? string.Empty,
            GetPermissions(
                permissions,
                OpenIddictConstants.Permissions.Prefixes.Endpoint),
            GetPermissions(
                permissions,
                OpenIddictConstants.Permissions.Prefixes.GrantType),
            GetPermissions(
                permissions,
                OpenIddictConstants.Permissions.Prefixes.ResponseType),
            GetPermissions(
                permissions,
                OpenIddictConstants.Permissions.Prefixes.Scope),
            DeserializeStringArray(application.RedirectUris)
                .OrderBy(uri => uri, StringComparer.OrdinalIgnoreCase)
                .ToList(),
            DeserializeStringArray(application.PostLogoutRedirectUris)
                .OrderBy(uri => uri, StringComparer.OrdinalIgnoreCase)
                .ToList());
    }

    private static IReadOnlyList<string> DeserializeStringArray(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<string[]>(value) ?? [];
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException(
                "The OpenIddict application contains invalid JSON configuration.",
                exception);
        }
    }

    private static IReadOnlyList<string> GetPermissions(
        IEnumerable<string> permissions,
        string prefix)
    {
        return permissions
            .Where(permission =>
                permission.StartsWith(prefix, StringComparison.Ordinal))
            .Select(permission =>
                FormatPermission(prefix, permission[prefix.Length..]))
            .OrderBy(permission => permission, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string FormatPermission(
        string prefix,
        string permission)
    {
        return prefix switch
        {
            OpenIddictConstants.Permissions.Prefixes.Endpoint =>
                FormatEndpointPermission(permission),

            OpenIddictConstants.Permissions.Prefixes.GrantType =>
                FormatGrantTypePermission(permission),

            OpenIddictConstants.Permissions.Prefixes.ResponseType =>
                FormatResponseTypePermission(permission),

            OpenIddictConstants.Permissions.Prefixes.Scope =>
                FormatScopePermission(permission),

            _ => FormatUnknownValue(permission)
        };
    }

    private static string FormatEndpointPermission(string permission)
    {
        return permission switch
        {
            "authorization" => "Authorization",
            "end_session" => "End session",
            "introspection" => "Introspection",
            "revocation" => "Revocation",
            "token" => "Token",
            _ => FormatUnknownValue(permission)
        };
    }

    private static string FormatGrantTypePermission(string permission)
    {
        return permission switch
        {
            "authorization_code" => "Authorization code",
            "client_credentials" => "Client credentials",
            "implicit" => "Implicit",
            "password" => "Password",
            "refresh_token" => "Refresh token",
            _ => FormatUnknownValue(permission)
        };
    }

    private static string FormatResponseTypePermission(string permission)
    {
        return permission switch
        {
            "code" => "Code",
            "code id_token" => "Code and ID token",
            "code id_token token" => "Code, ID token and access token",
            "code token" => "Code and access token",
            "id_token" => "ID token",
            "id_token token" => "ID token and access token",
            "none" => "None",
            "token" => "Access token",
            _ => FormatUnknownValue(permission)
        };
    }

    private static string FormatScopePermission(string permission)
    {
        return permission switch
        {
            "address" => "Address",
            "email" => "Email",
            "offline_access" => "Offline access",
            "openid" => "OpenID",
            "phone" => "Phone",
            "profile" => "Profile",
            "roles" => "Roles",
            _ => FormatUnknownValue(permission)
        };
    }

    private static string FormatUnknownValue(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        var words = value
            .Replace('_', ' ')
            .Replace('-', ' ')
            .Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries);

        return string.Join(
            " ",
            words.Select(word =>
                char.ToUpperInvariant(word[0]) + word[1..]));
    }
}

public sealed record ClientSummary(
    string ClientId,
    string DisplayName,
    string ClientType,
    string ConsentType);

public sealed record ClientApplicationDetails(
    string ClientId,
    string DisplayName,
    string ClientType,
    string ConsentType,
    IReadOnlyList<string> EndpointPermissions,
    IReadOnlyList<string> GrantTypePermissions,
    IReadOnlyList<string> ResponseTypePermissions,
    IReadOnlyList<string> ScopePermissions,
    IReadOnlyList<string> RedirectUris,
    IReadOnlyList<string> PostLogoutRedirectUris);