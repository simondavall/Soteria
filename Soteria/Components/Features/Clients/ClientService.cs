using System.Text.Json;
using FluentValidation.Results;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Soteria.Components.Features.Shared;
using Soteria.Data;

namespace Soteria.Components.Features.Clients;

public sealed class ClientService
{
    private readonly SoteriaDbContext _dbContext;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IMudValidator<CreateClientRequest> _createClientValidator;

    public ClientService(
        SoteriaDbContext dbContext, 
        IOpenIddictApplicationManager applicationManager, 
        IMudValidator<CreateClientRequest> createClientValidator)
    {
        _dbContext = dbContext;
        _applicationManager = applicationManager;
        _createClientValidator = createClientValidator;
    }
    
    public async Task CreateClientAsync(CreateClientRequest request, CancellationToken cancellationToken = default)
    {
        var validationResult = await _createClientValidator.ValidateAsync(request, cancellationToken);
        if (!validationResult.IsValid)
        {
            throw new ClientValidationFailureException(validationResult.Errors);
        }
        
        var clientId = ValidateRequiredValue(request.ClientId, nameof(CreateClientRequest.ClientId),
            "Client ID is required.");
        var displayName = ValidateRequiredValue(request.DisplayName, nameof(CreateClientRequest.DisplayName),
            "Display name is required.");

        ValidateClientSecret(request.ClientSecret);

        var clientHost = NormaliseClientHost(request.ClientHost);
        var existingApplication = await _applicationManager.FindByClientIdAsync(clientId, cancellationToken);
        
        if (existingApplication is not null)
        {
            throw new ClientValidationException(
                nameof(CreateClientRequest.ClientId), 
                "A client application with this client ID already exists.");
        }

        var descriptor =
            new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                DisplayName = displayName,
                ClientSecret = request.ClientSecret
            };

        descriptor.RedirectUris.Add(new Uri($"{clientHost}/signin-oidc", UriKind.Absolute));
        descriptor.PostLogoutRedirectUris.Add(new Uri($"{clientHost}/signout-callback-oidc", UriKind.Absolute));

        OpenIddictApplicationDefaults.Apply(descriptor);

        await _applicationManager.CreateAsync(descriptor, cancellationToken);
    }

    public async Task<IReadOnlyList<ClientSummary>> GetClientsAsync(CancellationToken cancellationToken = default)
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

    public async Task<ClientApplicationDetails?> GetClientAsync(string clientId, CancellationToken cancellationToken = default)
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
            GetPermissions(permissions, OpenIddictConstants.Permissions.Prefixes.Endpoint),
            GetPermissions(permissions, OpenIddictConstants.Permissions.Prefixes.GrantType),
            GetPermissions(permissions, OpenIddictConstants.Permissions.Prefixes.ResponseType),
            GetPermissions(permissions, OpenIddictConstants.Permissions.Prefixes.Scope),
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

    private static IReadOnlyList<string> GetPermissions(IEnumerable<string> permissions, string prefix)
    {
        return permissions
            .Where(permission => permission.StartsWith(prefix, StringComparison.Ordinal))
            .Select(permission => FormatPermission(prefix, permission[prefix.Length..]))
            .OrderBy(permission => permission, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string FormatPermission(string prefix, string permission)
    {
        return prefix switch
        {
            OpenIddictConstants.Permissions.Prefixes.Endpoint => FormatEndpointPermission(permission),
            OpenIddictConstants.Permissions.Prefixes.GrantType => FormatGrantTypePermission(permission),
            OpenIddictConstants.Permissions.Prefixes.ResponseType => FormatResponseTypePermission(permission),
            OpenIddictConstants.Permissions.Prefixes.Scope => FormatScopePermission(permission),
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
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);

        return string.Join(" ", words.Select(word => char.ToUpperInvariant(word[0]) + word[1..]));
    }

    private static string ValidateRequiredValue(string value, string propertyName, string errorMessage)
    {
        var normalisedValue = value.Trim();

        if (string.IsNullOrWhiteSpace(normalisedValue))
        {
            throw new ClientValidationException(propertyName, errorMessage);
        }

        return normalisedValue;
    }

    private static void ValidateClientSecret(string clientSecret)
    {
        if (string.IsNullOrWhiteSpace(clientSecret))
        {
            throw new ClientValidationException(
                nameof(CreateClientRequest.ClientSecret),
                "Client secret is required.");
        }
    }

    private static string NormaliseClientHost(string value)
    {
        var clientHost = ValidateRequiredValue(
            value,
            nameof(CreateClientRequest.ClientHost),
            "Client host is required.");

        if (!Uri.TryCreate(clientHost, UriKind.Absolute, out var uri) ||
            string.IsNullOrWhiteSpace(uri.Scheme) ||
            string.IsNullOrWhiteSpace(uri.Host))
        {
            throw new ClientValidationException(
                nameof(CreateClientRequest.ClientHost),
                "Enter a valid absolute client host URI. E.g. https://example.com:7276");
        }

        if (!string.IsNullOrEmpty(uri.Query))
        {
            throw new ClientValidationException(
                nameof(CreateClientRequest.ClientHost),
                "The client host must not contain a query string.");
        }
        
        if (!string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ClientValidationException(
                nameof(CreateClientRequest.ClientHost),
                "The client host must not contain a fragment.");
        }

        return clientHost.TrimEnd('/');
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

public sealed class ClientValidationException(string propertyName, string message) : Exception(message)
{
    public string PropertyName { get; } = propertyName;
}

public sealed class ClientValidationFailureException(List<ValidationFailure> errors) : Exception()
{
    public List<ValidationFailure> Errors { get; } = errors;
}