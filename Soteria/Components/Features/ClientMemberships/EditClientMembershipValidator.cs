using FluentValidation;
using Soteria.Components.Features.ClientMemberships.Queries;
using Soteria.Components.Features.Shared;
using Soteria.Data.Authorization;

namespace Soteria.Components.Features.ClientMemberships;

public sealed class EditClientMembershipValidator : AbstractValidator<EditClientMembershipRequest>,
    IMudValidator<EditClientMembershipRequest>
{
    private readonly IClientMembershipLookup _clientMembershipLookup;

    public EditClientMembershipValidator(IClientMembershipLookup clientMembershipLookup)
    {
        _clientMembershipLookup = clientMembershipLookup;

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
            .WithMessage("One or more selected Application Roles do not belong " +
                         "to this client application.");

        RuleFor(request => request.MembershipLevel)
            .MustAsync(ClientWillRetainAdministratorAsync)
            .WithMessage("The final Client Administrator cannot be demoted. " +
                         "Assign another Client Administrator before changing " +
                         "this membership.");
    }

    public Func<object, string, Task<IEnumerable<string>>> ValidateValueAsync => ValidatePropertyAsync;

    private static bool RoleSelectionsAreValid(EditClientMembershipRequest request, HashSet<Guid> selectedRoleIds)
    {
        var availableRoleIds = request.AvailableApplicationRoleIds.ToHashSet();
        return selectedRoleIds.All(availableRoleIds.Contains);
    }

    private async Task<bool> ClientWillRetainAdministratorAsync(EditClientMembershipRequest request,
        MembershipLevel requestedMembershipLevel, CancellationToken cancellationToken)
    {
        if (requestedMembershipLevel == MembershipLevel.Administrator)
        {
            return true;
        }

        var membership =
            await _clientMembershipLookup.GetValidationStateAsync(request.UserId, request.ClientMembershipId, cancellationToken);
        if (membership is null)
        {
            return true;
        }

        if (membership.MembershipLevel != MembershipLevel.Administrator)
        {
            return true;
        }

        return await _clientMembershipLookup.AnotherClientAdministratorExistsAsync(membership.ApplicationId, request.ClientMembershipId,
            cancellationToken);
    }

    private async Task<IEnumerable<string>> ValidatePropertyAsync(
        object model,
        string propertyName)
    {
        var context = ValidationContext<EditClientMembershipRequest>
                .CreateWithOptions((EditClientMembershipRequest)model, options => options.IncludeProperties(propertyName));

        var result = await ValidateAsync(context);

        return result.Errors.Select(error => error.ErrorMessage);
    }
}