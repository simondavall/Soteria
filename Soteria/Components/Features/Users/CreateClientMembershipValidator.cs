using FluentValidation;
using Soteria.Components.Features.Clients.Queries;
using Soteria.Components.Features.Shared;

namespace Soteria.Components.Features.Users;

public sealed class CreateClientMembershipValidator : AbstractValidator<CreateClientMembershipRequest>, IMudValidator<CreateClientMembershipRequest>
{
    private readonly IClientApplicationLookup _clientApplicationLookup;

    public CreateClientMembershipValidator(IClientApplicationLookup clientApplicationLookup)
    {
        _clientApplicationLookup = clientApplicationLookup;

        RuleFor(request => request.UserId)
            .NotEmpty();

        RuleFor(request => request.ClientId)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .WithMessage("Select a client application.")
            .MustAsync(ClientExistsAsync)
            .WithMessage(
                "The selected client application could not be found.");

        RuleFor(request => request.MembershipLevel)
            .IsInEnum();
    }

    private async Task<bool> ClientExistsAsync(string clientId, CancellationToken cancellationToken)
    {
        return await _clientApplicationLookup.ClientIdExistsAsync(clientId, cancellationToken);
    }

    public Func<object, string, Task<IEnumerable<string>>> ValidateValueAsync => ValidatePropertyAsync;

    private async Task<IEnumerable<string>> ValidatePropertyAsync(object model, string propertyName)
    {
        var context =
            ValidationContext<CreateClientMembershipRequest>
                .CreateWithOptions(
                    (CreateClientMembershipRequest)model,
                    options => options.IncludeProperties(propertyName));

        var result = await ValidateAsync(context);

        return result.Errors.Select(error => error.ErrorMessage);
    }
}