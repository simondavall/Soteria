using FluentValidation;
using FluentValidation.Results;
using Microsoft.EntityFrameworkCore;
using Soteria.Components.Features.Authorization;
using Soteria.Components.Features.ClientMemberships.Queries;
using Soteria.Data;
using Soteria.Data.Authorization;
using Soteria.Data.OpenIddict;

namespace Soteria.Components.Features.ClientMemberships;

public interface IClientMembershipService
{
    Task<IReadOnlyList<ClientMembershipDetailsModel>> GetForUserAsync(Guid userId, CancellationToken cancellationToken = default);
    Task<EditClientMembershipRequest?> GetForEditAsync(Guid userId, Guid clientMembershipId, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ClientMembershipApplicationRoleItem>> GetApplicationRolesAsync(Guid userId, Guid clientMembershipId,
        CancellationToken cancellationToken = default);
    Task CreateAsync(CreateClientMembershipRequest request, CancellationToken cancellationToken = default);
    Task UpdateAsync(EditClientMembershipRequest request, CancellationToken cancellationToken = default);
    Task RemoveAsync(RemoveClientMembershipRequest request, CancellationToken cancellationToken = default);
}

public sealed class ClientMembershipService : IClientMembershipService
{
    private readonly SoteriaDbContext _dbContext;
    private readonly IValidator<CreateClientMembershipRequest> _createValidator;
    private readonly IValidator<EditClientMembershipRequest> _editValidator;
    private readonly IValidator<RemoveClientMembershipRequest> _removeValidator;
    private readonly ICurrentUserContext _currentUserContext;

    public ClientMembershipService(
        SoteriaDbContext dbContext,
        IValidator<CreateClientMembershipRequest> createValidator,
        IValidator<EditClientMembershipRequest> editValidator,
        IValidator<RemoveClientMembershipRequest> removeValidator,
        ICurrentUserContext currentUserContext)
    {
        _dbContext = dbContext;
        _createValidator = createValidator;
        _editValidator = editValidator;
        _removeValidator = removeValidator;
        _currentUserContext = currentUserContext;
    }


    public async Task CreateAsync(CreateClientMembershipRequest request, CancellationToken cancellationToken = default)
    {
        var validationResult = await _createValidator.ValidateAsync(request, cancellationToken);
        if (!validationResult.IsValid)
        {
            throw new CreateClientMembershipValidationException(
                validationResult.Errors);
        }

        var userExists = await _dbContext.Users
            .AsNoTracking()
            .AnyAsync(user => user.Id == request.UserId, cancellationToken);

        if (!userExists)
        {
            throw new InvalidOperationException($"The user '{request.UserId}' could not be found.");
        }

        var application = await _dbContext
            .Set<SoteriaApplication>()
            .SingleOrDefaultAsync(item => item.ClientId == request.ClientId, cancellationToken);

        if (application is null)
        {
            throw new CreateClientMembershipValidationException(
            [
                new ValidationFailure(nameof(CreateClientMembershipRequest.ClientId), "The selected client application could not be found.")
            ]);
        }

        await EnsureCanAdministerClientAsync(application.Id, cancellationToken);

        var duplicateExists =
            await _dbContext.ClientMemberships
                .AsNoTracking()
                .AnyAsync(membership =>
                        membership.UserId == request.UserId &&
                        membership.ApplicationId == application.Id,
                    cancellationToken);

        if (duplicateExists)
        {
            throw CreateDuplicateMembershipException();
        }

        var membership =
            new ClientMembership
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
                    .AnyAsync(item =>
                            item.UserId == request.UserId &&
                            item.ApplicationId == application.Id,
                        cancellationToken);

            if (!membershipNowExists)
            {
                throw;
            }

            throw CreateDuplicateMembershipException();
        }
    }

    public async Task<IReadOnlyList<ClientMembershipDetailsModel>> GetForUserAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var administrationScope = await _currentUserContext.GetAdministrationScopeAsync(cancellationToken);

        if (administrationScope is { IsSoteriaAdministrator: false, AdministeredClientIds.Count: 0 })
        {
            return [];
        }

        var query = _dbContext.ClientMemberships.AsNoTracking().Where(membership => membership.UserId == userId);

        if (!administrationScope.IsSoteriaAdministrator)
        {
            query = query.WhereClientMembershipAdministered(administrationScope);
        }

        var memberships =
            await query
                .OrderBy(membership => membership.Application.DisplayName)
                .ThenBy(membership => membership.Application.ClientId)
                .ThenBy(membership => membership.Id)
                .Select(membership =>
                    new ClientMembershipQueryResult(
                        membership.Id,
                        membership.Application.DisplayName ?? membership.Application.ClientId ?? string.Empty,
                        membership.MembershipLevel))
                .ToListAsync(cancellationToken);

        if (memberships.Count == 0)
        {
            return [];
        }

        var membershipIds = memberships
            .Select(membership => membership.ClientMembershipId)
            .ToList();

        var roleAssignments =
            await _dbContext.ClientMembershipApplicationRoles
                .AsNoTracking()
                .Where(assignment => membershipIds.Contains(assignment.ClientMembershipId) &&
                                     assignment.ClientMembership.UserId == userId)
                .OrderBy(assignment => assignment.ApplicationRole.DisplayName)
                .ThenBy(assignment => assignment.ApplicationRole.Name)
                .ThenBy(assignment => assignment.ApplicationRole.Id)
                .Select(assignment =>
                    new ClientMembershipRoleQueryResult(
                        assignment.ClientMembershipId,
                        assignment.ApplicationRole.DisplayName))
                .ToListAsync(cancellationToken);

        var rolesByMembership =
            roleAssignments
                .GroupBy(assignment => assignment.ClientMembershipId)
                .ToDictionary(
                    group => group.Key,
                    group =>
                        (IReadOnlyList<string>)group
                            .Select(assignment => assignment.ApplicationRoleName)
                            .ToList());

        return memberships
            .Select(membership =>
                new ClientMembershipDetailsModel(
                    membership.ClientMembershipId,
                    membership.ApplicationName,
                    membership.MembershipLevel.ToString(),
                    rolesByMembership.GetValueOrDefault(
                        membership.ClientMembershipId,
                        [])))
            .ToList();
    }

    public async Task<EditClientMembershipRequest?> GetForEditAsync(Guid userId, Guid clientMembershipId,
        CancellationToken cancellationToken = default)
    {
        var administrationScope = await _currentUserContext.GetAdministrationScopeAsync(cancellationToken);

        if (administrationScope is { IsSoteriaAdministrator: false, AdministeredClientIds.Count: 0 })
        {
            return null;
        }

        var query =
            _dbContext.ClientMemberships
                .AsNoTracking()
                .Where(membership =>
                    membership.Id == clientMembershipId &&
                    membership.UserId == userId);

        if (!administrationScope.IsSoteriaAdministrator)
        {
            query = query.WhereClientMembershipAdministered(administrationScope);
        }

        var membership =
            await query
                .Select(item =>
                    new
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

        var applicationRoleIds =
            await _dbContext.ApplicationRoles
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
                    assignment.ClientMembershipId == membership.Id &&
                    assignment.ClientMembership.UserId == userId)
                .Select(assignment => assignment.ApplicationRoleId)
                .ToHashSetAsync(cancellationToken);

        return new EditClientMembershipRequest
        {
            UserId = membership.UserId,
            ClientMembershipId = membership.Id,
            ClientId = membership.ClientId ?? string.Empty,
            ApplicationName = membership.DisplayName ?? membership.ClientId ?? string.Empty,
            MembershipLevel = membership.MembershipLevel,
            AvailableApplicationRoleIds = applicationRoleIds,
            SelectedApplicationRoleIds = selectedRoleIds
        };
    }

    public async Task<IReadOnlyList<ClientMembershipApplicationRoleItem>> GetApplicationRolesAsync(Guid userId, Guid clientMembershipId,
        CancellationToken cancellationToken = default)
    {
        var administrationScope = await _currentUserContext.GetAdministrationScopeAsync(cancellationToken);

        if (administrationScope is { IsSoteriaAdministrator: false, AdministeredClientIds.Count: 0 })
        {
            return [];
        }

        var query =
            _dbContext.ClientMemberships
                .AsNoTracking()
                .Where(membership =>
                    membership.Id == clientMembershipId &&
                    membership.UserId == userId);

        if (!administrationScope.IsSoteriaAdministrator)
        {
            query = query.WhereClientMembershipAdministered(administrationScope);
        }

        var membership = await query
            .Select(item => new { item.ApplicationId })
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
            .Select(role =>
                new ClientMembershipApplicationRoleItem(
                    role.Id,
                    role.Name,
                    role.DisplayName,
                    role.Description))
            .ToListAsync(cancellationToken);
    }

    public async Task UpdateAsync(EditClientMembershipRequest request, CancellationToken cancellationToken = default)
    {
        await EnsureCanAdministerClientMembershipAsync(request.UserId, request.ClientMembershipId, cancellationToken);

        var validationResult = await _editValidator.ValidateAsync(request, cancellationToken);
        if (!validationResult.IsValid)
        {
            throw new EditClientMembershipValidationException(validationResult.Errors);
        }

        var membership =
            await _dbContext.ClientMemberships
                .Include(item => item.Application)
                .Include(item => item.ApplicationRoleAssignments)
                .SingleOrDefaultAsync(item =>
                        item.Id == request.ClientMembershipId &&
                        item.UserId == request.UserId,
                    cancellationToken);

        if (membership is null)
        {
            throw new ClientMembershipNotFoundException(request.UserId, request.ClientMembershipId);
        }

        await EnsureClientWillRetainAdministratorAsync(membership, request.MembershipLevel, membershipWillBeRemoved: false, cancellationToken);

        if (!string.Equals(membership.Application.ClientId, request.ClientId, StringComparison.Ordinal))
        {
            throw new EditClientMembershipValidationException(
            [
                new ValidationFailure(nameof(EditClientMembershipRequest.ClientId),
                    "The client application associated with this membership cannot be changed.")
            ]);
        }

        var selectedRoleIds = request.SelectedApplicationRoleIds.Distinct().ToHashSet();

        var validRoleIds =
            await _dbContext.ApplicationRoles
                .AsNoTracking()
                .Where(role =>
                    role.ApplicationId == membership.ApplicationId &&
                    selectedRoleIds.Contains(role.Id))
                .Select(role => role.Id)
                .ToListAsync(cancellationToken);

        if (validRoleIds.Count != selectedRoleIds.Count)
        {
            throw new EditClientMembershipValidationException(
            [
                new ValidationFailure(nameof(EditClientMembershipRequest.SelectedApplicationRoleIds),
                    "One or more selected Application Roles do not belong to this client application.")
            ]);
        }

        membership.MembershipLevel = request.MembershipLevel;

        var existingRoleIds = membership.ApplicationRoleAssignments
            .Select(assignment => assignment.ApplicationRoleId)
            .ToHashSet();

        var assignmentsToRemove = membership.ApplicationRoleAssignments
            .Where(assignment => !selectedRoleIds.Contains(assignment.ApplicationRoleId))
            .ToList();

        var roleIdsToAdd = selectedRoleIds
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
                new ValidationFailure(nameof(EditClientMembershipRequest.SelectedApplicationRoleIds),
                    "The Client Membership could not be updated because one or " +
                    "more role assignments are no longer valid.")
            ]);
        }
    }

    public async Task RemoveAsync(RemoveClientMembershipRequest request, CancellationToken cancellationToken = default)
    {
        await EnsureCanAdministerClientMembershipAsync(request.UserId, request.ClientMembershipId, cancellationToken);

        var validationResult = await _removeValidator.ValidateAsync(request, cancellationToken);
        if (!validationResult.IsValid)
        {
            throw new RemoveClientMembershipValidationException(validationResult.Errors);
        }

        var membership =
            await _dbContext.ClientMemberships
                .SingleOrDefaultAsync(item =>
                        item.Id == request.ClientMembershipId &&
                        item.UserId == request.UserId,
                    cancellationToken);

        if (membership is null)
        {
            throw new ClientMembershipNotFoundException(request.UserId, request.ClientMembershipId);
        }

        await EnsureClientWillRetainAdministratorAsync(membership, membership.MembershipLevel, membershipWillBeRemoved: true, cancellationToken);

        _dbContext.ClientMemberships.Remove(membership);

        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    private static CreateClientMembershipValidationException CreateDuplicateMembershipException()
    {
        return new CreateClientMembershipValidationException(
        [
            new ValidationFailure(nameof(CreateClientMembershipRequest.ClientId),
                "The user already belongs to this client application.")
        ]);
    }

    private async Task EnsureCanAdministerClientMembershipAsync(Guid userId, Guid clientMembershipId, CancellationToken cancellationToken)
    {
        var administrationScope = await _currentUserContext.GetAdministrationScopeAsync(cancellationToken);
        if (administrationScope.IsSoteriaAdministrator)
        {
            return;
        }

        var administeredClientIds = administrationScope.AdministeredClientIds.ToArray();
        if (administeredClientIds.Length == 0)
        {
            throw new UnauthorizedAccessException("You cannot administer this Client Membership.");
        }

        IEnumerable<Guid> clientIds = administeredClientIds;

        var canAdminister =
            await _dbContext.ClientMemberships
                .AsNoTracking()
                .AnyAsync(membership =>
                        membership.Id == clientMembershipId &&
                        membership.UserId == userId &&
                        clientIds.Contains(membership.ApplicationId),
                    cancellationToken);

        if (!canAdminister)
        {
            throw new UnauthorizedAccessException("You cannot administer this Client Membership.");
        }
    }

    private async Task EnsureCanAdministerClientAsync(Guid applicationId, CancellationToken cancellationToken)
    {
        var administrationScope = await _currentUserContext.GetAdministrationScopeAsync(cancellationToken);
        if (administrationScope.IsSoteriaAdministrator)
        {
            return;
        }

        if (!administrationScope.AdministeredClientIds.Contains(applicationId))
        {
            throw new UnauthorizedAccessException("You cannot administer this client application.");
        }
    }

    private async Task EnsureClientWillRetainAdministratorAsync(
        ClientMembership membership,
        MembershipLevel requestedMembershipLevel,
        bool membershipWillBeRemoved,
        CancellationToken cancellationToken)
    {
        if (membership.MembershipLevel != MembershipLevel.Administrator)
        {
            return;
        }

        if (!membershipWillBeRemoved && requestedMembershipLevel == MembershipLevel.Administrator)
        {
            return;
        }

        var anotherAdministratorExists =
            await _dbContext.ClientMemberships
                .AsNoTracking()
                .AnyAsync(item =>
                        item.ApplicationId == membership.ApplicationId &&
                        item.Id != membership.Id &&
                        item.MembershipLevel == MembershipLevel.Administrator,
                    cancellationToken);

        if (anotherAdministratorExists)
        {
            return;
        }

        if (membershipWillBeRemoved)
        {
            throw new RemoveClientMembershipValidationException(
            [
                new ValidationFailure(nameof(RemoveClientMembershipRequest.ClientMembershipId),
                    "The final Client Administrator cannot be removed. " +
                    "Assign another Client Administrator before removing this membership.")
            ]);
        }

        throw new EditClientMembershipValidationException(
        [
            new ValidationFailure(nameof(EditClientMembershipRequest.MembershipLevel),
                "The final Client Administrator cannot be demoted. " +
                "Assign another Client Administrator before changing this membership.")
        ]);
    }
}

public sealed record ClientMembershipDetailsModel(
    Guid ClientMembershipId,
    string ApplicationName,
    string MembershipLevel,
    IReadOnlyList<string> ApplicationRoles);

public sealed record ClientMembershipApplicationRoleItem(
    Guid ApplicationRoleId,
    string Name,
    string DisplayName,
    string? Description);

internal sealed record ClientMembershipQueryResult(
    Guid ClientMembershipId,
    string ApplicationName,
    MembershipLevel MembershipLevel);

internal sealed record ClientMembershipRoleQueryResult(
    Guid ClientMembershipId,
    string ApplicationRoleName);

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

public sealed class RemoveClientMembershipValidationException(IReadOnlyList<ValidationFailure> failures)
    : Exception("Client Membership removal validation failed.")
{
    public IReadOnlyList<ValidationFailure> Failures { get; } = failures;
}

public sealed class ClientMembershipNotFoundException(Guid userId, Guid clientMembershipId)
    : Exception($"Client Membership '{clientMembershipId}' could not be found for user '{userId}'.");