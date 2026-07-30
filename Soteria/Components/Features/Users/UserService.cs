using System.Text;
using System.Text.Encodings.Web;
using FluentValidation;
using FluentValidation.Results;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Soteria.Components.Features.Authorization;
using Soteria.Components.Features.Users.Queries;
using Soteria.Data;
using Soteria.Data.Authorization;

namespace Soteria.Components.Features.Users;

public sealed class UserService
{
    private readonly SoteriaDbContext _dbContext;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IUserStore<ApplicationUser> _userStore;
    private readonly IEmailSender<ApplicationUser> _emailSender;
    private readonly NavigationManager _navigationManager;
    private readonly IValidator<CreateUserRequest> _createUserValidator;
    private readonly IValidator<EditUserRequest> _editUserValidator;
    private readonly ICurrentUserContext _currentUserContext;

    public UserService(
        SoteriaDbContext dbContext,
        UserManager<ApplicationUser> userManager,
        IUserStore<ApplicationUser> userStore,
        IEmailSender<ApplicationUser> emailSender,
        NavigationManager navigationManager,
        IValidator<CreateUserRequest> createUserValidator,
        IValidator<EditUserRequest> editUserValidator,
        ICurrentUserContext currentUserContext)
    {
        _dbContext = dbContext;
        _userManager = userManager;
        _userStore = userStore;
        _emailSender = emailSender;
        _navigationManager = navigationManager;
        _createUserValidator = createUserValidator;
        _editUserValidator = editUserValidator;
        _currentUserContext = currentUserContext;
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
        var administrationScope = await _currentUserContext.GetAdministrationScopeAsync(cancellationToken);

        if (administrationScope is { IsSoteriaAdministrator: false, AdministeredClientIds.Count: 0 })
        {
            return [];
        }

        var now = DateTimeOffset.UtcNow;
        var query = _dbContext.Users
            .AsNoTracking();

        if (!administrationScope.IsSoteriaAdministrator)
        {
            query = query.WhereUserAdministered(administrationScope);
        }

        return await query
            .OrderBy(user => user.UserName)
            .ThenBy(user => user.Id)
            .Select(user =>
                new UserSummary(
                    user.Id,
                    user.UserName ?? string.Empty,
                    user.DisplayName,
                    user.Email ?? string.Empty,
                    user.EmailConfirmed,
                    user.LockoutEnd.HasValue && user.LockoutEnd.Value > now))
            .ToListAsync(cancellationToken);
    }

    public async Task<UserDetailsModel?> GetUserAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var administrationScope = await _currentUserContext.GetAdministrationScopeAsync(cancellationToken);
        if (administrationScope is { IsSoteriaAdministrator: false, AdministeredClientIds.Count: 0 })
        {
            return null;
        }

        var now = DateTimeOffset.UtcNow;

        return await _dbContext.Users
            .AsNoTracking()
            .Where(user => user.Id == userId)
            .Select(
                user =>
                    new UserDetailsModel(
                        user.Id,
                        user.UserName ?? string.Empty,
                        user.DisplayName,
                        user.Email ?? string.Empty,
                        user.EmailConfirmed,
                        user.LockoutEnd.HasValue
                        && user.LockoutEnd.Value > now,
                        user.LockoutEnd,
                        _dbContext.UserSystemRoles.Any(assignment => 
                            assignment.UserId == user.Id && 
                            assignment.SystemRoleId == SystemRoleIds.SoteriaAdministrator)))
            .SingleOrDefaultAsync(cancellationToken);
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
            LockoutEnd = user.LockoutEnd,
            IsSoteriaAdministrator = user.IsSoteriaAdministrator
        };
    }

    public async Task UpdateUserAsync(EditUserRequest request, CancellationToken cancellationToken = default)
    {
        await EnsureCanAdministerUserAsync(request.UserId, cancellationToken);

        var validationResult = await _editUserValidator.ValidateAsync(request, cancellationToken);
        if (!validationResult.IsValid)
        {
            throw new EditUserValidationException(validationResult.Errors);
        }

        await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);

        var user = await _userManager.FindByIdAsync(request.UserId.ToString());
        if (user is null)
        {
            throw new InvalidOperationException($"The user '{request.UserId}' could not be found.");
        }

        var administratorAssignment =
            await _dbContext.UserSystemRoles
                .SingleOrDefaultAsync(assignment =>
                        assignment.UserId == request.UserId &&
                        assignment.SystemRoleId == SystemRoleIds.SoteriaAdministrator,
                    cancellationToken);

        var currentlyIsAdministrator = administratorAssignment is not null;
        var administratorStatusIsChanging = currentlyIsAdministrator != request.IsSoteriaAdministrator;
        if (administratorStatusIsChanging && !await _currentUserContext.IsSoteriaAdministratorAsync(cancellationToken))
        {
            throw new UnauthorizedAccessException("Only Soteria Administrators can change Soteria Administrator assignments.");
        }

        if (currentlyIsAdministrator && !request.IsSoteriaAdministrator)
        {
            var anotherAdministratorExists =
                await _dbContext.UserSystemRoles
                    .AsNoTracking()
                    .AnyAsync(
                        assignment => assignment.UserId != request.UserId && assignment.SystemRoleId == SystemRoleIds.SoteriaAdministrator,
                        cancellationToken);

            if (!anotherAdministratorExists)
            {
                throw CreateFinalSoteriaAdministratorException();
            }

            _dbContext.UserSystemRoles.Remove(administratorAssignment!);
        }
        else if (!currentlyIsAdministrator && request.IsSoteriaAdministrator)
        {
            _dbContext.UserSystemRoles.Add(
                new UserSystemRole
                {
                    UserId = request.UserId,
                    SystemRoleId = SystemRoleIds.SoteriaAdministrator
                });
        }

        if (request.UnlockRequested)
        {
            var identityResult = await _userManager.SetLockoutEndDateAsync(user, null);
            if (!identityResult.Succeeded)
            {
                throw new EditUserIdentityException(identityResult.Errors);
            }
        }

        try
        {
            await _dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            throw new EditUserValidationException(
            [
                new ValidationFailure(nameof(EditUserRequest.IsSoteriaAdministrator),
                    "The Soteria Administrator assignment could not be updated. Reload the user and try again.")
            ]);
        }
    }

    private static EditUserValidationException CreateFinalSoteriaAdministratorException()
    {
        return new EditUserValidationException(
        [
            new ValidationFailure(
                nameof(EditUserRequest.IsSoteriaAdministrator),
                "The final Soteria Administrator cannot be removed. " +
                "Assign another Soteria Administrator before removing this assignment.")
        ]);
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

    private async Task EnsureCanAdministerUserAsync(Guid userId, CancellationToken cancellationToken)
    {
        var administrationScope = await _currentUserContext.GetAdministrationScopeAsync(cancellationToken);
        if (administrationScope.IsSoteriaAdministrator)
        {
            return;
        }

        var administeredClientIds = administrationScope.AdministeredClientIds.ToArray();

        var canAdminister =
            await _dbContext.ClientMemberships
                .AsNoTracking()
                .AnyAsync(membership => 
                        membership.UserId == userId && 
                        ((IEnumerable<Guid>)administeredClientIds).Contains(membership.ApplicationId),
                    cancellationToken);

        if (!canAdminister)
        {
            throw new UnauthorizedAccessException("You cannot administer this user.");
        }
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
    DateTimeOffset? LockoutEnd,
    bool IsSoteriaAdministrator);

public sealed class CreateUserValidationException(IReadOnlyList<ValidationFailure> failures) : Exception("User validation failed.")
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

public sealed class EditUserValidationException(IReadOnlyList<ValidationFailure> failures) : Exception("User validation failed.")
{
    public IReadOnlyList<ValidationFailure> Failures { get; } = failures;
}