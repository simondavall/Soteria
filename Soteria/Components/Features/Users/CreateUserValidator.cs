using FluentValidation;
using Soteria.Components.Features.Shared;
using Soteria.Components.Features.Users.Queries;

namespace Soteria.Components.Features.Users;

public sealed class CreateUserValidator : AbstractValidator<CreateUserRequest>, IMudValidator<CreateUserRequest>
{
    private readonly IUserLookup _userLookup;

    public CreateUserValidator(IUserLookup userLookup)
    {
        _userLookup = userLookup;

        RuleFor(request => request.Email)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .EmailAddress();

        WhenAsync(IsNewUserAsync, () =>
        {
            RuleFor(request => request.Password)
                .NotEmpty()
                .MinimumLength(6);

            RuleFor(request => request.ConfirmPassword)
                .NotEmpty()
                .Equal(request => request.Password)
                .WithMessage(
                    "The password and confirmation password do not match.");
        });
    }

    private async Task<bool> IsNewUserAsync(CreateUserRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Email))
        {
            return true;
        }

        return !await _userLookup.EmailExistsAsync(request.Email, cancellationToken);
    }

    public Func<object, string, Task<IEnumerable<string>>> ValidateValueAsync => ValidatePropertyAsync;

    private async Task<IEnumerable<string>> ValidatePropertyAsync(object model, string propertyName)
    {
        var context = ValidationContext<CreateUserRequest>
            .CreateWithOptions((CreateUserRequest)model, options => options.IncludeProperties(propertyName));

        var result = await ValidateAsync(context);

        return result.Errors.Select(error => error.ErrorMessage);
    }
}