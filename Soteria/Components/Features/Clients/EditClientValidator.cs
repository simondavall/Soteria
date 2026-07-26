using FluentValidation;
using Soteria.Components.Features.Shared;

namespace Soteria.Components.Features.Clients;

public sealed class EditClientValidator : AbstractValidator<EditClientRequest>, IMudValidator<EditClientRequest>
{
    public EditClientValidator()
    {
        RuleFor(x => x.DisplayName)
            .NotEmpty();

        RuleFor(x => x.ClientHost)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .Must(BeAbsoluteUri)
            .WithMessage("Enter a valid client host. E.g. https://example.com")
            .Must(NotHaveQueryString)
            .WithMessage("The client host must not contain a query string.")
            .Must(NotHaveAFragment)
            .WithMessage("The client host must not contain a fragment.");
    }

    public Func<object, string, Task<IEnumerable<string>>> ValidateValueAsync => ValidatePropertyAsync;

    private async Task<IEnumerable<string>> ValidatePropertyAsync(object model, string propertyName)
    {
        var context = ValidationContext<EditClientRequest>
            .CreateWithOptions((EditClientRequest)model, options => options.IncludeProperties(propertyName));

        var result = await ValidateAsync(context);

        return result.Errors.Select(error => error.ErrorMessage);
    }

    private static bool BeAbsoluteUri(string clientHost)
    {
        return Uri.TryCreate(clientHost, UriKind.Absolute, out var uri)
            && !string.IsNullOrWhiteSpace(uri.Scheme)
            && !string.IsNullOrWhiteSpace(uri.Host);
    }

    private static bool NotHaveQueryString(string clientHost)
    {
        Uri.TryCreate(clientHost, UriKind.Absolute, out var uri);

        return string.IsNullOrEmpty(uri?.Query);
    }

    private static bool NotHaveAFragment(string clientHost)
    {
        Uri.TryCreate(clientHost, UriKind.Absolute, out var uri);

        return string.IsNullOrEmpty(uri?.Fragment);
    }
}
