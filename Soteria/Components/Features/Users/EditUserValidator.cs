using FluentValidation;
using Soteria.Components.Features.Shared;
using Soteria.Components.Features.Users.Queries;

namespace Soteria.Components.Features.Users;

public sealed class EditUserValidator : AbstractValidator<EditUserRequest>, IMudValidator<EditUserRequest>
{
    private readonly IUserLookup _userLookup;

    public EditUserValidator(IUserLookup userLookup)
    {
        _userLookup = userLookup;

        RuleFor(request => request.IsSoteriaAdministrator)
            .MustAsync(CanUpdateSoteriaAdministratorStatusAsync)
            .WithMessage(
                "The final Soteria Administrator cannot be removed. " +
                "Assign another Soteria Administrator before removing this assignment.");
    }

    private async Task<bool> CanUpdateSoteriaAdministratorStatusAsync(EditUserRequest request, bool isSoteriaAdministrator, CancellationToken cancellationToken)
    {
        if (isSoteriaAdministrator)
        {
            return true;
        }

        var currentlyIsAdministrator = await _userLookup.HasSoteriaAdministratorAssignmentAsync(request.UserId, cancellationToken);
        if (!currentlyIsAdministrator)
        {
            return true;
        }

        return await _userLookup.AnotherSoteriaAdministratorExistsAsync(request.UserId, cancellationToken);
    }

    public Func<object, string, Task<IEnumerable<string>>> ValidateValueAsync => ValidatePropertyAsync;

    private async Task<IEnumerable<string>> ValidatePropertyAsync(object model, string propertyName)
    {
        var context =
            ValidationContext<EditUserRequest>
                .CreateWithOptions((EditUserRequest)model, options => options.IncludeProperties(propertyName));

        var result = await ValidateAsync(context);
        return result.Errors.Select(error => error.ErrorMessage);
    }
}