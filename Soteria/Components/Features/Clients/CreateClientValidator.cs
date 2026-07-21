using FluentValidation;
using Soteria.Components.Features.Clients.Queries;
using Soteria.Components.Features.Shared;

namespace Soteria.Components.Features.Clients;

public sealed class CreateClientValidator : AbstractValidator<CreateClientRequest>, IMudValidator<CreateClientRequest>
{
    private readonly IClientApplicationLookup _clientApplicationLookup;

    public CreateClientValidator(IClientApplicationLookup clientApplicationLookup)
    {
        _clientApplicationLookup = clientApplicationLookup;
        RuleFor(x => x.ClientId)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .MustAsync(IsUniqueAsync)
            .WithMessage("A client application with this client ID already exists.");

        RuleFor(x => x.DisplayName)
            .NotEmpty();
        
        RuleFor(x => x.ClientSecret)
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
    
    private async Task<bool> IsUniqueAsync(string clientId, CancellationToken cancellationToken)
    {
        return !await _clientApplicationLookup.ClientIdExistsAsync(clientId.Trim(), cancellationToken);
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
        return string.IsNullOrEmpty(uri?.Query ?? null);
    }

    private static bool NotHaveAFragment(string clientHost)
    {
        Uri.TryCreate(clientHost, UriKind.Absolute, out var uri);
        return string.IsNullOrEmpty(uri?.Fragment ?? null);
    }

    public Func<object, string, Task<IEnumerable<string>>> ValidateValueAsync => ValidatePropertyAsync;

    private async Task<IEnumerable<string>> ValidatePropertyAsync(object model, string propertyName)
    {
        var context = ValidationContext<CreateClientRequest>
            .CreateWithOptions((CreateClientRequest)model, options => options.IncludeProperties(propertyName));

        var result = await ValidateAsync(context);

        return result.Errors.Select(error => error.ErrorMessage);
    }
}