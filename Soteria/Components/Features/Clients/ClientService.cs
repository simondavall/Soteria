using System.Text.Json;
using FluentValidation;
using FluentValidation.Results;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using Soteria.Data;
using Soteria.Data.Authorization;
using Soteria.Data.OpenIddict;

namespace Soteria.Components.Features.Clients;

public sealed class ClientService
{
    private readonly SoteriaDbContext _dbContext;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IValidator<CreateClientRequest> _createClientValidator;
    private readonly IValidator<EditClientRequest> _editClientValidator;
    private readonly IValidator<CreateApplicationRoleRequest> _createApplicationRoleValidator;
    private readonly IValidator<EditApplicationRoleRequest> _editApplicationRoleValidator;

    public ClientService(
        SoteriaDbContext dbContext,
        IOpenIddictApplicationManager applicationManager,
        IValidator<CreateClientRequest> createClientValidator,
        IValidator<EditClientRequest> editClientValidator,
        IValidator<CreateApplicationRoleRequest> createApplicationRoleValidator,
        IValidator<EditApplicationRoleRequest> editApplicationRoleValidator)
    {
        _dbContext = dbContext;
        _applicationManager = applicationManager;
        _createClientValidator = createClientValidator;
        _editClientValidator = editClientValidator;
        _createApplicationRoleValidator = createApplicationRoleValidator;
        _editApplicationRoleValidator = editApplicationRoleValidator;
    }

    public async Task CreateClientAsync(CreateClientRequest request, CancellationToken cancellationToken = default)
    {
        request.ClientId = request.ClientId.Trim();
        request.DisplayName = request.DisplayName.Trim();
        request.ClientHost = request.ClientHost.Trim().TrimEnd('/');

        var validationResult = await _createClientValidator.ValidateAsync(request, cancellationToken);
        if (!validationResult.IsValid)
        {
            throw new CreateClientValidationException(validationResult.Errors);
        }

        var descriptor =
            new OpenIddictApplicationDescriptor
            {
                ClientId = request.ClientId,
                DisplayName = request.DisplayName,
                ClientSecret = request.ClientSecret
            };

        descriptor.RedirectUris.Add(new Uri($"{request.ClientHost}/signin-oidc", UriKind.Absolute));
        descriptor.PostLogoutRedirectUris.Add(new Uri($"{request.ClientHost}/signout-callback-oidc", UriKind.Absolute));

        OpenIddictApplicationDefaults.Apply(descriptor);

        await _applicationManager.CreateAsync(descriptor, cancellationToken);
    }

    public async Task<EditClientRequest?> GetClientForEditAsync(string clientId,
        CancellationToken cancellationToken = default)
    {
        var application = await GetClientAsync(clientId, cancellationToken);
        if (application is null)
        {
            return null;
        }

        return new EditClientRequest
        {
            ClientId = application.ClientId,
            DisplayName = application.DisplayName,
            IsEnabled = application.IsEnabled,
            ClientHost = GetClientHost(application.RedirectUris)
        };
    }

    public async Task<IReadOnlyList<ClientSummary>> GetClientsAsync(CancellationToken cancellationToken = default)
    {
        return await _dbContext
            .Set<SoteriaApplication>()
            .AsNoTracking()
            .Where(application => application.ClientId != null)
            .OrderBy(application =>
                application.DisplayName ?? application.ClientId)
            .Select(application => new ClientSummary(
                application.ClientId!,
                application.DisplayName ?? application.ClientId!,
                application.ClientType ?? string.Empty,
                application.ConsentType ?? string.Empty,
                application.IsEnabled))
            .ToListAsync(cancellationToken);
    }

    public async Task<ClientApplicationDetails?> GetClientAsync(string clientId,
        CancellationToken cancellationToken = default)
    {
        var application = await _dbContext
            .Set<SoteriaApplication>()
            .AsNoTracking()
            .Where(application => application.ClientId == clientId)
            .Select(application => new
            {
                application.ClientId,
                application.DisplayName,
                application.ClientType,
                application.ConsentType,
                application.IsEnabled,
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
            application.IsEnabled,
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

    public async Task<IReadOnlyList<ApplicationRoleSummary>> GetApplicationRolesAsync(string clientId, CancellationToken cancellationToken = default)
    {
        return await _dbContext.ApplicationRoles
            .AsNoTracking()
            .Where(role => role.Application.ClientId == clientId)
            .OrderBy(role => role.DisplayName)
            .ThenBy(role => role.Name)
            .Select(role => new ApplicationRoleSummary(
                role.Name,
                role.DisplayName,
                role.Description))
            .ToListAsync(cancellationToken);
    }

    public async Task<EditApplicationRoleRequest?> GetApplicationRoleForEditAsync(string clientId, string name, CancellationToken cancellationToken = default)
    {
        return await _dbContext.ApplicationRoles
            .AsNoTracking()
            .Where(role =>
                role.Application.ClientId == clientId &&
                role.Name == name)
            .Select(role => new EditApplicationRoleRequest
            {
                ClientId = clientId,
                Name = role.Name,
                DisplayName = role.DisplayName,
                Description = role.Description
            })
            .SingleOrDefaultAsync(cancellationToken);
    }
    
    public async Task<DeleteApplicationRoleRequest?> GetApplicationRoleForRemovalAsync(string clientId, string name, CancellationToken cancellationToken = default)
    {
        return await _dbContext.ApplicationRoles
            .AsNoTracking()
            .Where(role =>
                role.Application.ClientId == clientId &&
                role.Name == name)
            .Select(role => new DeleteApplicationRoleRequest
            {
                ClientId = clientId,
                Name = role.Name,
                AssignmentCount = role.ClientMembershipAssignments.Count
            })
            .SingleOrDefaultAsync(cancellationToken);
    }
    
    public async Task RemoveApplicationRoleAsync(string clientId, string name, CancellationToken cancellationToken = default)
    {
        var role = await _dbContext.ApplicationRoles
            .SingleOrDefaultAsync(
                role =>
                    role.Application.ClientId == clientId &&
                    role.Name == name,
                cancellationToken);

        if (role is null)
        {
            throw new ApplicationRoleNotFoundException(clientId, name);
        }

        _dbContext.ApplicationRoles.Remove(role);
        
        await _dbContext.SaveChangesAsync(cancellationToken);
    }
    
    public async Task UpdateApplicationRoleAsync(EditApplicationRoleRequest request, CancellationToken cancellationToken = default)
    {
        request.DisplayName = request.DisplayName.Trim();
        request.Description = string.IsNullOrWhiteSpace(request.Description) ? null : request.Description.Trim();

        var validationResult = await _editApplicationRoleValidator.ValidateAsync(request, cancellationToken);

        if (!validationResult.IsValid)
        {
            throw new EditApplicationRoleValidationException(validationResult.Errors);
        }

        var role = await _dbContext.ApplicationRoles
            .Include(item => item.Application)
            .SingleOrDefaultAsync(
                item =>
                    item.Application.ClientId == request.ClientId &&
                    item.Name == request.Name,
                cancellationToken);

        if (role is null)
        {
            throw new InvalidOperationException(
                $"The application role '{request.Name}' could not be found for client application '{request.ClientId}'.");
        }

        role.DisplayName = request.DisplayName;
        role.Description = request.Description;

        await _dbContext.SaveChangesAsync(cancellationToken);
    }
    
    public async Task CreateApplicationRoleAsync(CreateApplicationRoleRequest request, CancellationToken cancellationToken = default)
    {
        request.DisplayName = request.DisplayName.Trim();
        request.Description = string.IsNullOrWhiteSpace(request.Description) ? null : request.Description.Trim();

        var validationResult = await _createApplicationRoleValidator.ValidateAsync(request, cancellationToken);

        if (!validationResult.IsValid)
        {
            throw new CreateApplicationRoleValidationException(validationResult.Errors);
        }

        var application = await _dbContext
            .Set<SoteriaApplication>()
            .SingleOrDefaultAsync(
                item => item.ClientId == request.ClientId,
                cancellationToken);

        if (application is null)
        {
            throw new InvalidOperationException(
                $"The client application '{request.ClientId}' could not be found.");
        }

        var role = new ApplicationRole
        {
            Id = Guid.NewGuid(),
            ApplicationId = application.Id,
            Name = request.Name,
            DisplayName = request.DisplayName,
            Description = request.Description
        };

        _dbContext.ApplicationRoles.Add(role);

        try
        {
            await _dbContext.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            var duplicateExists =
                await _dbContext.ApplicationRoles
                    .AsNoTracking()
                    .AnyAsync(
                        item =>
                            item.ApplicationId == application.Id &&
                            item.Name == request.Name,
                        cancellationToken);

            if (!duplicateExists)
            {
                throw;
            }

            throw new CreateApplicationRoleValidationException(
            [
                new ValidationFailure(
                    nameof(CreateApplicationRoleRequest.Name),
                    "An application role with this name already exists for this client application.")
            ]);
        }
    }

    public async Task UpdateClientAsync(EditClientRequest request, CancellationToken cancellationToken = default)
    {
        request.DisplayName = request.DisplayName.Trim();
        request.ClientHost = request.ClientHost.Trim().TrimEnd('/');

        var validationResult = await _editClientValidator.ValidateAsync(request, cancellationToken);

        if (!validationResult.IsValid)
        {
            throw new EditClientValidationException(validationResult.Errors);
        }

        var application = await _applicationManager.FindByClientIdAsync(request.ClientId, cancellationToken);
        if (application is null)
        {
            throw new InvalidOperationException(
                $"The client application '{request.ClientId}' could not be found.");
        }

        var descriptor = new OpenIddictApplicationDescriptor();

        await _applicationManager.PopulateAsync(descriptor, application, cancellationToken);

        if (application is not SoteriaApplication soteriaApplication)
        {
            throw new InvalidOperationException(
                "The OpenIddict application is not using the Soteria application entity.");
        }

        soteriaApplication.IsEnabled = request.IsEnabled;

        descriptor.DisplayName = request.DisplayName;

        descriptor.RedirectUris.Clear();
        descriptor.RedirectUris.Add(new Uri(request.RedirectUri, UriKind.Absolute));

        descriptor.PostLogoutRedirectUris.Clear();
        descriptor.PostLogoutRedirectUris.Add(new Uri(request.PostLogoutRedirectUri, UriKind.Absolute));

        await _applicationManager.UpdateAsync(application, descriptor, cancellationToken);

        if (!string.IsNullOrWhiteSpace(request.ClientSecret))
        {
            await _applicationManager.UpdateAsync(application, request.ClientSecret, cancellationToken);
        }
    }

    private static string GetClientHost(IReadOnlyList<string> redirectUris)
    {
        const string redirectPath = "/signin-oidc";

        var redirectUri = redirectUris.SingleOrDefault();

        if (redirectUri is null ||
            !redirectUri.EndsWith(
                redirectPath,
                StringComparison.OrdinalIgnoreCase))
        {
            return string.Empty;
        }

        return redirectUri[..^redirectPath.Length].TrimEnd('/');
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
}

public sealed record ApplicationRoleSummary(
    string Name,
    string DisplayName,
    string? Description);

public sealed record ClientSummary(
    string ClientId,
    string DisplayName,
    string ClientType,
    string ConsentType,
    bool IsEnabled);

public sealed record ClientApplicationDetails(
    string ClientId,
    string DisplayName,
    string ClientType,
    string ConsentType,
    bool IsEnabled,
    IReadOnlyList<string> EndpointPermissions,
    IReadOnlyList<string> GrantTypePermissions,
    IReadOnlyList<string> ResponseTypePermissions,
    IReadOnlyList<string> ScopePermissions,
    IReadOnlyList<string> RedirectUris,
    IReadOnlyList<string> PostLogoutRedirectUris);

public sealed class CreateClientValidationException(IReadOnlyList<ValidationFailure> failures)
    : Exception("Client application validation failed.")
{
    public IReadOnlyList<ValidationFailure> Failures { get; } = failures;
}

public sealed class EditClientValidationException(IReadOnlyList<ValidationFailure> failures)
    : Exception("Client application validation failed.")
{
    public IReadOnlyList<ValidationFailure> Failures { get; } = failures;
}

public sealed class CreateApplicationRoleValidationException(IReadOnlyList<ValidationFailure> failures)
    : Exception("Application role validation failed.")
{
    public IReadOnlyList<ValidationFailure> Failures { get; } = failures;
}

public sealed class EditApplicationRoleValidationException(IReadOnlyList<ValidationFailure> failures)
    : Exception("Application role validation failed.")
{
    public IReadOnlyList<ValidationFailure> Failures { get; } = failures;
}

public sealed class ApplicationRoleNotFoundException(string clientId, string name)
    : Exception($"The Application Role '{name}' could not be found for client application '{clientId}'.");