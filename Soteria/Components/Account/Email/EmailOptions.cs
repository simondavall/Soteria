namespace Soteria.Components.Account.Email;

public sealed class EmailOptions
{
    public const string SectionName = "Soteria:Email";
    public string Host { get; init; } = string.Empty;
    public int Port { get; init; }
    public EmailSecurity Security { get; init; }
    public string DisplayName { get; init; } = string.Empty;
    public string SenderAddress { get; init; } = string.Empty;
    public string Username { get; init; } = string.Empty;
    public string Password { get; init; } = string.Empty;
}