using System.Text;
using System.Text.Encodings.Web;
using FluentValidation;
using FluentValidation.Results;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Soteria.Data;
using Soteria.Data.Authorization;
using Soteria.Data.OpenIddict;

namespace Soteria.Components.Features.Users;

public sealed class UserService
{
    private readonly SoteriaDbContext _dbContext;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IUserStore<ApplicationUser> _userStore;
    private readonly IEmailSender<ApplicationUser> _emailSender;
    private readonly NavigationManager _navigationManager;
    private readonly IValidator<CreateUserRequest> _createUserValidator;
    private readonly IValidator<CreateClientMembershipRequest> _createClientMembershipValidator;
    private readonly IValidator<EditClientMembershipRequest> _editClientMembershipValidator;

    public UserService(
        SoteriaDbContext dbContext,
        UserManager<ApplicationUser> userManager,
        IUserStore<ApplicationUser> userStore,
        IEmailSender<ApplicationUser> emailSender,
        NavigationManager navigationManager,
        IValidator<CreateUserRequest> createUserValidator,
        IValidator<CreateClientMembershipRequest> createClientMembershipValidator,
        IValidator<EditClientMembershipRequest> editClientMembershipValidator)
    {
        _dbContext = dbContext;
        _userManager = userManager;
        _userStore = userStore;
        _emailSender = emailSender;
        _navigationManager = navigationManager;
        _createUserValidator = createUserValidator;
        _createClientMembershipValidator = createClientMembershipValidator;
        _editClientMembershipValidator = editClientMembershipValidator;
    }

    public async Task<CreateUserResult> CreateUserAsync(CreateUserRequest request, CancellationToken cancellationToken = default)
    {
        request.Email = request.Email.Trim();

        var existingUser = await _userManager.FindByEmailAsync(request.Email);
        if (existingUser is not null)
        {
            return new CreateUserResult(existingUser.Id, false);
        }

        var validationResult = await _createUserValidator.ValidateAsync(request, cancellationToken);
        if (!validationResult.IsValid)
        {
            throw new CreateUserValidationException(validationResult.Errors);
        }

        var user = new ApplicationUser();

        await _userStore.SetUserNameAsync(user, request.Email, cancellationToken);

        var emailStore = GetEmailStore();
        await emailStore.SetEmailAsync(user, request.Email, cancellationToken);

        var identityResult = await _userManager.CreateAsync(user, request.Password);
        if (!identityResult.Succeeded)
        {
            throw new CreateUserIdentityException(identityResult.Errors);
        }

        await SendConfirmationEmailAsync(user);

        return new CreateUserResult(user.Id, true);
    }

    public async Task<IReadOnlyList<UserSummary>> GetUsersAsync(CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;

        return await _dbContext.Users
            .AsNoTracking()
            .OrderBy(user => user.UserName)
            .ThenBy(user => user.Id)
            .Select(user => new UserSummary(
                user.Id,
                user.UserName ?? string.Empty,
                user.DisplayName,
                user.Email ?? string.Empty,
                user.EmailConfirmed,
                user.LockoutEnd.HasValue
                && user.LockoutEnd.Value > now))
            .ToListAsync(cancellationToken);
    }

    public async Task<UserDetailsModel?> GetUserAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;

        return await _dbContext.Users
            .AsNoTracking()
            .Where(user => user.Id == userId)
            .Select(user => new UserDetailsModel(
                user.Id,
                user.UserName ?? string.Empty,
                user.DisplayName,
                user.Email ?? string.Empty,
                user.EmailConfirmed,
                user.LockoutEnd.HasValue
                && user.LockoutEnd.Value > now,
                user.LockoutEnd))
            .SingleOrDefaultAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<ClientMembershipDetailsModel>> GetClientMembershipsAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var memberships = await _dbContext.ClientMemberships
            .AsNoTracking()
            .Where(membership => membership.UserId == userId)
            .OrderBy(membership => membership.Application.DisplayName)
            .ThenBy(membership => membership.Application.ClientId)
            .ThenBy(membership => membership.Id)
            .Select(membership => new ClientMembershipQueryResult(
                membership.Id,
                membership.Application.DisplayName
                ?? membership.Application.ClientId
                ?? string.Empty,
                membership.MembershipLevel))
            .ToListAsync(cancellationToken);

        if (memberships.Count == 0)
        {
            return [];
        }

        var membershipIds = memberships
            .Select(membership => membership.ClientMembershipId)
            .ToList();

        var roleAssignments = await _dbContext.ClientMembershipApplicationRoles
            .AsNoTracking()
            .Where(assignment =>
                membershipIds.Contains(assignment.ClientMembershipId)
                && assignment.ClientMembership.UserId == userId)
            .OrderBy(assignment => assignment.ApplicationRole.DisplayName)
            .ThenBy(assignment => assignment.ApplicationRole.Name)
            .ThenBy(assignment => assignment.ApplicationRole.Id)
            .Select(assignment => new ClientMembershipRoleQueryResult(
                assignment.ClientMembershipId,
                assignment.ApplicationRole.DisplayName))
            .ToListAsync(cancellationToken);

        var rolesByMembership = roleAssignments
            .GroupBy(assignment => assignment.ClientMembershipId)
            .ToDictionary(
                group => group.Key,
                group => (IReadOnlyList<string>)group
                    .Select(assignment => assignment.ApplicationRoleName)
                    .ToList());

        return memberships
            .Select(membership => new ClientMembershipDetailsModel(
                membership.ClientMembershipId,
                membership.ApplicationName,
                membership.MembershipLevel.ToString(),
                rolesByMembership.GetValueOrDefault(
                    membership.ClientMembershipId,
                    [])))
            .ToList();
    }

    public async Task<EditClientMembershipRequest?> GetClientMembershipForEditAsync(Guid userId, Guid clientMembershipId, CancellationToken cancellationToken = default)
    {
        var membership = await _dbContext.ClientMemberships
            .AsNoTracking()
            .Where(item => item.Id == clientMembershipId && item.UserId == userId)
            .Select(item => new
            {
                item.Id,
                item.UserId,
                item.ApplicationId,
                item.Application.ClientId,
                item.Application.DisplayName,
                item.MembershipLevel
            })
            .SingleOrDefaultAsync(cancellationToken);

        if (membership is null)
        {
            return null;
        }

        var applicationRoles = await _dbContext.ApplicationRoles
            .AsNoTracking()
            .Where(role => role.ApplicationId == membership.ApplicationId)
            .OrderBy(role => role.DisplayName)
            .ThenBy(role => role.Name)
            .ThenBy(role => role.Id)
            .Select(role => role.Id)
            .ToListAsync(cancellationToken);

        var selectedRoleIds =
            await _dbContext.ClientMembershipApplicationRoles
                .AsNoTracking()
                .Where(assignment =>
                    assignment.ClientMembershipId == membership.Id
                    && assignment.ClientMembership.UserId == userId)
                .Select(assignment => assignment.ApplicationRoleId)
                .ToHashSetAsync(cancellationToken);

        return new EditClientMembershipRequest
        {
            UserId = membership.UserId,
            ClientMembershipId = membership.Id,
            ClientId = membership.ClientId ?? string.Empty,
            ApplicationName = membership.DisplayName ?? membership.ClientId ?? string.Empty,
            MembershipLevel = membership.MembershipLevel,
            AvailableApplicationRoleIds = applicationRoles,
            SelectedApplicationRoleIds = selectedRoleIds
        };
    }
    
    public async Task<IReadOnlyList<ClientMembershipApplicationRoleItem>> GetClientMembershipApplicationRolesAsync(Guid userId, Guid clientMembershipId, CancellationToken cancellationToken = default)
    {
        var membership = await _dbContext.ClientMemberships
            .AsNoTracking()
            .Where(item => item.Id == clientMembershipId && item.UserId == userId)
            .Select(item => new
            {
                item.ApplicationId
            })
            .SingleOrDefaultAsync(cancellationToken);

        if (membership is null)
        {
            return [];
        }

        return await _dbContext.ApplicationRoles
            .AsNoTracking()
            .Where(role => role.ApplicationId == membership.ApplicationId)
            .OrderBy(role => role.DisplayName)
            .ThenBy(role => role.Name)
            .ThenBy(role => role.Id)
            .Select(role => new ClientMembershipApplicationRoleItem(
                role.Id,
                role.Name,
                role.DisplayName,
                role.Description))
            .ToListAsync(cancellationToken);
    }
    
    public async Task UpdateClientMembershipAsync(EditClientMembershipRequest request, CancellationToken cancellationToken = default)
    {
        var validationResult = await _editClientMembershipValidator.ValidateAsync(request, cancellationToken);

        if (!validationResult.IsValid)
        {
            throw new EditClientMembershipValidationException(validationResult.Errors);
        }

        var membership = await _dbContext.ClientMemberships
            .Include(item => item.Application)
            .Include(item => item.ApplicationRoleAssignments)
            .SingleOrDefaultAsync(
                item =>
                    item.Id == request.ClientMembershipId
                    && item.UserId == request.UserId,
                cancellationToken);

        if (membership is null)
        {
            throw new ClientMembershipNotFoundException(request.UserId, request.ClientMembershipId);
        }

        if (!string.Equals(membership.Application.ClientId, request.ClientId, StringComparison.Ordinal))
        {
            throw new EditClientMembershipValidationException(
            [
                new ValidationFailure(nameof(EditClientMembershipRequest.ClientId),
                    "The client application associated with this membership cannot be changed.")
            ]);
        }

        var selectedRoleIds =
            request.SelectedApplicationRoleIds
                .Distinct()
                .ToHashSet();

        var validRoleIds = await _dbContext.ApplicationRoles
            .AsNoTracking()
            .Where(role => role.ApplicationId == membership.ApplicationId && selectedRoleIds.Contains(role.Id))
            .Select(role => role.Id)
            .ToListAsync(cancellationToken);

        if (validRoleIds.Count != selectedRoleIds.Count)
        {
            throw new EditClientMembershipValidationException(
            [
                new ValidationFailure(
                    nameof(EditClientMembershipRequest.SelectedApplicationRoleIds),
                    "One or more selected Application Roles do not belong to this client application.")
            ]);
        }

        membership.MembershipLevel = request.MembershipLevel;

        var existingRoleIds =
            membership.ApplicationRoleAssignments
                .Select(assignment => assignment.ApplicationRoleId)
                .ToHashSet();

        var assignmentsToRemove =
            membership.ApplicationRoleAssignments
                .Where(assignment => !selectedRoleIds.Contains(assignment.ApplicationRoleId))
                .ToList();

        var roleIdsToAdd =
            selectedRoleIds
                .Except(existingRoleIds)
                .ToList();

        if (assignmentsToRemove.Count > 0)
        {
            _dbContext.ClientMembershipApplicationRoles.RemoveRange(assignmentsToRemove);
        }

        foreach (var applicationRoleId in roleIdsToAdd)
        {
            _dbContext.ClientMembershipApplicationRoles.Add(
                new ClientMembershipApplicationRole
                {
                    ClientMembershipId = membership.Id,
                    ApplicationRoleId = applicationRoleId,
                    ApplicationId = membership.ApplicationId
                });
        }

        try
        {
            await _dbContext.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            throw new EditClientMembershipValidationException(
            [
                new ValidationFailure(
                    nameof(EditClientMembershipRequest.SelectedApplicationRoleIds),
                    "The Client Membership could not be updated because one or more role assignments are no longer valid.")
            ]);
        }
    }
    
    public async Task CreateClientMembershipAsync(CreateClientMembershipRequest request, CancellationToken cancellationToken = default) 
    {
        var validationResult = await _createClientMembershipValidator.ValidateAsync(request, cancellationToken);
        if (!validationResult.IsValid)
        {
            throw new CreateClientMembershipValidationException(validationResult.Errors);
        }

        var userExists = await _dbContext.Users
            .AsNoTracking()
            .AnyAsync(
                user => user.Id == request.UserId,
                cancellationToken);

        if (!userExists)
        {
            throw new InvalidOperationException($"The user '{request.UserId}' could not be found.");
        }

        var application = await _dbContext
            .Set<SoteriaApplication>()
            .SingleOrDefaultAsync(
                item => item.ClientId == request.ClientId,
                cancellationToken);

        if (application is null)
        {
            throw new CreateClientMembershipValidationException(
            [
                new ValidationFailure(
                    nameof(CreateClientMembershipRequest.ClientId),
                    "The selected client application could not be found.")
            ]);
        }

        var duplicateExists = await _dbContext.ClientMemberships
            .AsNoTracking()
            .AnyAsync(
                membership =>
                    membership.UserId == request.UserId
                    && membership.ApplicationId == application.Id,
                cancellationToken);

        if (duplicateExists)
        {
            throw CreateDuplicateMembershipException();
        }

        var membership = new ClientMembership
        {
            Id = Guid.NewGuid(),
            UserId = request.UserId,
            ApplicationId = application.Id,
            MembershipLevel = request.MembershipLevel,
            CreatedUtc = DateTime.UtcNow
        };

        _dbContext.ClientMemberships.Add(membership);

        try
        {
            await _dbContext.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            var membershipNowExists =
                await _dbContext.ClientMemberships
                    .AsNoTracking()
                    .AnyAsync(
                        item =>
                            item.UserId == request.UserId
                            && item.ApplicationId == application.Id,
                        cancellationToken);

            if (!membershipNowExists)
            {
                throw;
            }

            throw CreateDuplicateMembershipException();
        }
    }

    private static CreateClientMembershipValidationException CreateDuplicateMembershipException()
    {
        return new CreateClientMembershipValidationException(
        [
            new ValidationFailure(
                nameof(CreateClientMembershipRequest.ClientId),
                "The user already belongs to this client application.")
        ]);
    }
    
    public async Task<EditUserRequest?> GetUserForEditAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var user = await GetUserAsync(userId, cancellationToken);
        if (user is null)
        {
            return null;
        }

        return new EditUserRequest
        {
            UserId = user.UserId,
            UserName = user.UserName,
            DisplayName = user.DisplayName,
            Email = user.Email,
            EmailConfirmed = user.EmailConfirmed,
            IsLockedOut = user.IsLockedOut,
            LockoutEnd = user.LockoutEnd
        };
    }

    public async Task UpdateUserAsync(EditUserRequest request)
    {
        var user = await _userManager.FindByIdAsync(request.UserId.ToString());
        if (user is null)
        {
            throw new InvalidOperationException($"The user '{request.UserId}' could not be found.");
        }

        if (!request.UnlockRequested)
        {
            return;
        }

        var result = await _userManager.SetLockoutEndDateAsync(user, null);
        if (!result.Succeeded)
        {
            throw new EditUserIdentityException(result.Errors);
        }
    }

    private async Task SendConfirmationEmailAsync(ApplicationUser user)
    {
        var userId = await _userManager.GetUserIdAsync(user);
        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

        var callbackUrl =
            _navigationManager.GetUriWithQueryParameters(
                _navigationManager
                    .ToAbsoluteUri("Account/ConfirmEmail")
                    .AbsoluteUri,
                new Dictionary<string, object?>
                {
                    ["userId"] = userId,
                    ["code"] = code
                });

        await _emailSender.SendConfirmationLinkAsync(user, user.Email!, HtmlEncoder.Default.Encode(callbackUrl));
    }

    private IUserEmailStore<ApplicationUser> GetEmailStore()
    {
        if (!_userManager.SupportsUserEmail)
        {
            throw new NotSupportedException("The configured user store does not support email.");
        }

        return (IUserEmailStore<ApplicationUser>)_userStore;
    }
}

public sealed record CreateUserResult(
    Guid UserId,
    bool UserCreated);

public sealed record UserSummary(
    Guid UserId,
    string UserName,
    string? DisplayName,
    string Email,
    bool EmailConfirmed,
    bool IsLockedOut);

public sealed record UserDetailsModel(
    Guid UserId,
    string UserName,
    string? DisplayName,
    string Email,
    bool EmailConfirmed,
    bool IsLockedOut,
    DateTimeOffset? LockoutEnd);

public sealed record ClientMembershipDetailsModel(
    Guid ClientMembershipId,
    string ApplicationName,
    string MembershipLevel,
    IReadOnlyList<string> ApplicationRoles);

internal sealed record ClientMembershipQueryResult(
    Guid ClientMembershipId,
    string ApplicationName,
    MembershipLevel MembershipLevel);

internal sealed record ClientMembershipRoleQueryResult(
    Guid ClientMembershipId,
    string ApplicationRoleName);

public sealed class CreateUserValidationException(IReadOnlyList<ValidationFailure> failures)
    : Exception("User validation failed.")
{
    public IReadOnlyList<ValidationFailure> Failures { get; } = failures;
}

public sealed class CreateUserIdentityException(IEnumerable<IdentityError> errors) : Exception("User creation failed.")
{
    public IReadOnlyList<IdentityError> Errors { get; } = errors.ToList();
}

public sealed class EditUserIdentityException(IEnumerable<IdentityError> errors) : Exception("User update failed.")
{
    public IReadOnlyList<IdentityError> Errors { get; } = errors.ToList();
}

public sealed class CreateClientMembershipValidationException(IReadOnlyList<ValidationFailure> failures)
    : Exception("Client Membership validation failed.")
{
    public IReadOnlyList<ValidationFailure> Failures { get; } = failures;
}

public sealed class EditClientMembershipValidationException(IReadOnlyList<ValidationFailure> failures)
    : Exception("Client Membership validation failed.")
{
    public IReadOnlyList<ValidationFailure> Failures { get; } = failures;
}

public sealed class ClientMembershipNotFoundException(Guid userId, Guid clientMembershipId)
    : Exception($"Client Membership '{clientMembershipId}' could not be found for user '{userId}'.");