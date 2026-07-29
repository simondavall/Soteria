using FluentValidation;
using Soteria.Components.Features.Shared;
using Soteria.Components.Features.Users.Queries;
using Soteria.Data.Authorization;

namespace Soteria.Components.Features.Users;

public sealed class EditClientMembershipValidator : AbstractValidator<EditClientMembershipRequest>,
    IMudValidator<EditClientMembershipRequest>
{
    private readonly IUserLookup _userLookup;

    public EditClientMembershipValidator(IUserLookup userLookup)
    {
        _userLookup = userLookup;
        RuleFor(request => request.UserId)
            .NotEmpty();

        RuleFor(request => request.ClientMembershipId)
            .NotEmpty();

        RuleFor(request => request.ClientId)
            .NotEmpty();

        RuleFor(request => request.ApplicationName)
            .NotEmpty();

        RuleFor(request => request.MembershipLevel)
            .IsInEnum();

        RuleFor(request => request.SelectedApplicationRoleIds)
            .Must(RoleSelectionsAreValid)
            .WithMessage("One or more selected Application Roles do not belong to this client application.");

        RuleFor(request => request.MembershipLevel)
            .MustAsync(ClientWillRetainAdministratorAsync)
            .WithMessage("The final Client Administrator cannot be demoted. " +
                         "Assign another Client Administrator before changing this membership.");
    }

    private static bool RoleSelectionsAreValid(EditClientMembershipRequest request, HashSet<Guid> selectedRoleIds)
    {
        var availableRoleIds = request.AvailableApplicationRoleIds.ToHashSet();

        return selectedRoleIds.All(availableRoleIds.Contains);
    }

    public Func<object, string, Task<IEnumerable<string>>> ValidateValueAsync => ValidatePropertyAsync;

    private async Task<IEnumerable<string>> ValidatePropertyAsync(object model, string propertyName)
    {
        var context =
            ValidationContext<EditClientMembershipRequest>
                .CreateWithOptions(
                    (EditClientMembershipRequest)model,
                    options => options.IncludeProperties(propertyName));

        var result = await ValidateAsync(context);

        return result.Errors.Select(error => error.ErrorMessage);
    }

    private async Task<bool> ClientWillRetainAdministratorAsync(
        EditClientMembershipRequest request,
        MembershipLevel requestedMembershipLevel,
        CancellationToken cancellationToken)
    {
        if (requestedMembershipLevel == MembershipLevel.Administrator)
        {
            return true;
        }

        var membership =
            await _userLookup.GetClientMembershipValidationStateAsync(request.UserId, request.ClientMembershipId, cancellationToken);

        if (membership is null)
        {
            return true;
        }

        if (membership.MembershipLevel != MembershipLevel.Administrator)
        {
            return true;
        }

        return await _userLookup.AnotherClientAdministratorExistsAsync(membership.ApplicationId, request.ClientMembershipId,
            cancellationToken);
    }
}