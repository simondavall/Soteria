using FluentValidation;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using Soteria.Components.Features.Shared;
using Soteria.Data;

namespace Soteria.Components.Features.Clients;

public class CreateClientValidator : AbstractValidator<CreateClientRequest>, IMudValidator<CreateClientRequest>
{
    private readonly DbContext _dbContext;
    private HashSet<string>? _clientIds;

    public CreateClientValidator(SoteriaDbContext dbContext)
    {
        _dbContext = dbContext;
        RuleFor(x => x.ClientId)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .MustAsync(async (value, cancellationToken) => await IsUniqueAsync(value, cancellationToken))
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

    // private async Task<bool> IsUniqueAsync(string clientId)
    // {
    //     if (_clients.Count == 0)
    //     {
    //         _clients = await _clientService.GetClientsAsync();
    //     }
    //     var existingApplication = _clients.Where(x => x.ClientId == clientId);
    //     return !existingApplication.Any();
    // }
    
    private async Task<bool> IsUniqueAsync(string clientId, CancellationToken cancellationToken)
    {
        _clientIds ??= (await GetClientIdsAsync(cancellationToken))
            .ToHashSet(StringComparer.Ordinal);

        return !_clientIds.Contains(clientId);
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
    
    private async Task<IReadOnlyList<string>> GetClientIdsAsync(CancellationToken cancellationToken = default)
    {
        return await _dbContext
            .Set<OpenIddictEntityFrameworkCoreApplication<Guid>>()
            .AsNoTracking()
            .Select(x => x.ClientId!)
            .ToListAsync(cancellationToken);
    }
    
    public Func<object, string, Task<IEnumerable<string>>> ValidateValue => async (model, propertyName) =>
    {
        var result = await ValidateAsync(ValidationContext<CreateClientRequest>.CreateWithOptions((CreateClientRequest)model, x => x.IncludeProperties(propertyName)));
        return result.IsValid ? [] : result.Errors.Select(e => e.ErrorMessage);
    };
}