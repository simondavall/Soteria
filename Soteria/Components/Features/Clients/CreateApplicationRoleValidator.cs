using FluentValidation;
using Soteria.Components.Features.Clients.Queries;
using Soteria.Components.Features.Shared;

namespace Soteria.Components.Features.Clients;

public sealed class CreateApplicationRoleValidator : AbstractValidator<CreateApplicationRoleRequest>, IMudValidator<CreateApplicationRoleRequest>
{
    private readonly IApplicationRoleLookup _applicationRoleLookup;

    public CreateApplicationRoleValidator(IApplicationRoleLookup applicationRoleLookup)
    {
        _applicationRoleLookup = applicationRoleLookup;

        RuleFor(request => request.Name)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .MaximumLength(200)
            .Must(NotContainWhitespaceOrControlCharacters)
            .WithMessage("Name must not contain whitespace or control characters.")
            .MustAsync(IsUniqueAsync)
            .WithMessage("An application role with this name already exists for this client application.");

        RuleFor(request => request.DisplayName)
            .NotEmpty()
            .MaximumLength(200);

        RuleFor(request => request.Description)
            .MaximumLength(500);
    }

    private async Task<bool> IsUniqueAsync(CreateApplicationRoleRequest request, string name, CancellationToken cancellationToken)
    {
        return !await _applicationRoleLookup.NameExistsAsync(request.ClientId, name, cancellationToken);
    }

    private static bool NotContainWhitespaceOrControlCharacters(string name)
    {
        return name.All(character => !char.IsWhiteSpace(character) && !char.IsControl(character));
    }

    public Func<object, string, Task<IEnumerable<string>>> ValidateValueAsync => ValidatePropertyAsync;

    private async Task<IEnumerable<string>> ValidatePropertyAsync(object model, string propertyName)
    {
        var context = ValidationContext<CreateApplicationRoleRequest>
            .CreateWithOptions((CreateApplicationRoleRequest)model, options => options.IncludeProperties(propertyName));
        
        var result = await ValidateAsync(context);

        return result.Errors.Select(error => error.ErrorMessage);
    }
}