using FluentValidation;
using OpenIddict.Abstractions;
using Soteria.Components.Features.Clients.Models;

namespace Soteria.Components.Features.Clients;

public class ClientValidator : AbstractValidator<CreateClientModel>
{
    private readonly IOpenIddictApplicationManager _applicationManager;

    public ClientValidator(IOpenIddictApplicationManager applicationManager)
    {
        _applicationManager = applicationManager;

        RuleFor(x => x.ClientId)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .MustAsync(async (value, _) => await IsUniqueAsync(value))
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

    private async Task<bool> IsUniqueAsync(string clientId)
    {
        var existingApplication = await _applicationManager.FindByClientIdAsync(clientId);
        return existingApplication is null;
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
    
    public Func<object, string, Task<IEnumerable<string>>> ValidateValue => async (model, propertyName) =>
    {
        var result = await ValidateAsync(ValidationContext<CreateClientModel>.CreateWithOptions((CreateClientModel)model, x => x.IncludeProperties(propertyName)));
        return result.IsValid ? [] : result.Errors.Select(e => e.ErrorMessage);
    };
}