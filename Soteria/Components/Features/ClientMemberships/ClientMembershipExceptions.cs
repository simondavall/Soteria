using FluentValidation.Results;

namespace Soteria.Components.Features.ClientMemberships;

public sealed class CreateClientMembershipValidationException(
    IReadOnlyList<ValidationFailure> failures)
    : Exception("Client Membership validation failed.")
{
    public IReadOnlyList<ValidationFailure> Failures { get; } = failures;
}

public sealed class EditClientMembershipValidationException(
    IReadOnlyList<ValidationFailure> failures)
    : Exception("Client Membership validation failed.")
{
    public IReadOnlyList<ValidationFailure> Failures { get; } = failures;
}

public sealed class RemoveClientMembershipValidationException(
    IReadOnlyList<ValidationFailure> failures)
    : Exception("Client Membership removal validation failed.")
{
    public IReadOnlyList<ValidationFailure> Failures { get; } = failures;
}

public sealed class ClientMembershipNotFoundException(
    Guid userId,
    Guid clientMembershipId)
    : Exception(
        $"Client Membership '{clientMembershipId}' could not be found for user '{userId}'.");