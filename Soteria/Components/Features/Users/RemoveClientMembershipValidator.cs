using FluentValidation;
using Soteria.Components.Features.Users.Queries;
using Soteria.Data.Authorization;

namespace Soteria.Components.Features.Users;

public sealed class RemoveClientMembershipValidator : AbstractValidator<RemoveClientMembershipRequest>
{
    public RemoveClientMembershipValidator(IUserLookup userLookup)
    {
        RuleFor(request => request.UserId)
            .NotEmpty();

        RuleFor(request => request.ClientMembershipId)
            .NotEmpty();

        RuleFor(request => request)
            .MustAsync(
                async (request, cancellationToken) =>
                    await ClientWillRetainAdministratorAsync(
                        userLookup,
                        request,
                        cancellationToken))
            .WithName(nameof(RemoveClientMembershipRequest.ClientMembershipId))
            .WithMessage(
                "The final Client Administrator cannot be removed. " +
                "Assign another Client Administrator before removing this membership.");
    }

    private static async Task<bool> ClientWillRetainAdministratorAsync(
        IUserLookup userLookup,
        RemoveClientMembershipRequest request,
        CancellationToken cancellationToken)
    {
        var membership =
            await userLookup.GetClientMembershipValidationStateAsync(request.UserId, request.ClientMembershipId, cancellationToken);

        if (membership is null)
        {
            return true;
        }

        if (membership.MembershipLevel != MembershipLevel.Administrator)
        {
            return true;
        }

        return await userLookup.AnotherClientAdministratorExistsAsync(membership.ApplicationId, request.ClientMembershipId, 
            cancellationToken);
    }
}