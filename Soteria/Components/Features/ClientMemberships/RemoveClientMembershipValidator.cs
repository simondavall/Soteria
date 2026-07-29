using FluentValidation;
using Soteria.Components.Features.ClientMemberships.Queries;
using Soteria.Data.Authorization;

namespace Soteria.Components.Features.ClientMemberships;

public sealed class RemoveClientMembershipValidator : AbstractValidator<RemoveClientMembershipRequest>
{
    private readonly IClientMembershipLookup _clientMembershipLookup;

    public RemoveClientMembershipValidator(IClientMembershipLookup clientMembershipLookup)
    {
        _clientMembershipLookup = clientMembershipLookup;

        RuleFor(request => request.UserId)
            .NotEmpty();

        RuleFor(request => request.ClientMembershipId)
            .NotEmpty();

        RuleFor(request => request)
            .MustAsync(ClientWillRetainAdministratorAsync)
            .WithName(nameof(RemoveClientMembershipRequest.ClientMembershipId))
            .WithMessage("The final Client Administrator cannot be removed. " +
                         "Assign another Client Administrator before removing " +
                         "this membership.");
    }

    private async Task<bool> ClientWillRetainAdministratorAsync(RemoveClientMembershipRequest request, CancellationToken cancellationToken)
    {
        var membership = await _clientMembershipLookup
            .GetValidationStateAsync(request.UserId, request.ClientMembershipId, cancellationToken);

        if (membership is null)
        {
            return true;
        }

        if (membership.MembershipLevel != MembershipLevel.Administrator)
        {
            return true;
        }

        return await _clientMembershipLookup
            .AnotherClientAdministratorExistsAsync(membership.ApplicationId, request.ClientMembershipId, cancellationToken);
    }
}