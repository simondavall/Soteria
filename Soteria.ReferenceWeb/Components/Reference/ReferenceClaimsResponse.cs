namespace Soteria.ReferenceWeb.Components.Reference;

public sealed record ReferenceClaimsResponse(
    string? Name,
    string? Subject,
    string? Username,
    string? Email,
    string? AuthenticationType,
    string? RoleClaimType,
    IReadOnlyList<string> Roles,
    IReadOnlyList<ReferenceClaimResponse> Claims);

public sealed record ReferenceClaimResponse(
    string Type,
    string Value,
    string ValueType,
    string Issuer);