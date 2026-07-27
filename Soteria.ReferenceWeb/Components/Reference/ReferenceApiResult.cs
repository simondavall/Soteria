namespace Soteria.ReferenceWeb.Components.Reference;

public sealed record ReferenceApiResult<T>(
    bool Ok,
    int Status,
    string? Message,
    T? Data);