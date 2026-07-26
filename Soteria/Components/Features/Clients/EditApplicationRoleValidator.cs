using FluentValidation;
using Soteria.Components.Features.Shared;

namespace Soteria.Components.Features.Clients;

public sealed class EditApplicationRoleValidator : AbstractValidator<EditApplicationRoleRequest>, IMudValidator<EditApplicationRoleRequest>
{
    public EditApplicationRoleValidator()
    {
        RuleFor(request => request.DisplayName)
            .NotEmpty()
            .MaximumLength(200);

        RuleFor(request => request.Description)
            .MaximumLength(500);
    }

    public Func<object, string, Task<IEnumerable<string>>> ValidateValueAsync => ValidatePropertyAsync;

    private async Task<IEnumerable<string>> ValidatePropertyAsync(object model, string propertyName)
    {
        var context = ValidationContext<EditApplicationRoleRequest>
            .CreateWithOptions((EditApplicationRoleRequest)model, options => options.IncludeProperties(propertyName));

        var result = await ValidateAsync(context);

        return result.Errors.Select(error => error.ErrorMessage);
    }
}