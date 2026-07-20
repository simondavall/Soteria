using FluentValidation;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using Soteria.Components.Features.Clients.Models;

namespace Soteria.Components.Features.Clients;

public class ClientValidator : AbstractValidator<CreateClientModel>
{
    private readonly ClientService _clientService;
    private IReadOnlyList<ClientSummary> _clients = [];
    private readonly string[] _clientIds = [];

    public ClientValidator(ClientService clientService)
    {
        _clientService = clientService;
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
        if (_clients.Count == 0)
        {
            _clients = await _clientService.GetClientsAsync();
        }
        var existingApplication = _clients.Where(x => x.ClientId == clientId);
        return !existingApplication.Any();
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