using FluentValidation;
using Soteria.Components.Features.Shared;

namespace Soteria.Components.Features.Users;

public sealed class EditClientMembershipValidator : AbstractValidator<EditClientMembershipRequest>, IMudValidator<EditClientMembershipRequest>
{
    public EditClientMembershipValidator()
    {
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
            .WithMessage(
                "One or more selected Application Roles do not belong to this client application.");
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
}