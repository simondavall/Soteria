using MimeKit;

namespace Soteria.Components.Account.Email;

internal static class EmailOptionsLoader
{
    public static EmailOptions Load(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var options = new EmailOptions();

        configuration
            .GetSection(EmailOptions.SectionName)
            .Bind(options);

        Validate(options);

        return options;
    }

    private static void Validate(EmailOptions options)
    {
        ValidateRequiredValue(options.Host, $"{EmailOptions.SectionName}:Host");

        if (options.Port is < 1 or > 65535)
        {
            throw new InvalidOperationException(
                $"The configuration value '{EmailOptions.SectionName}:Port' must be between 1 and 65535.");
        }

        if (options.Security is not EmailSecurity.SslOnConnect and not EmailSecurity.StartTls)
        {
            throw new InvalidOperationException(
                $"The configuration value '{EmailOptions.SectionName}:Security' must be either " +
                "'SslOnConnect' or 'StartTls'.");
        }

        ValidateRequiredValue(options.DisplayName, $"{EmailOptions.SectionName}:DisplayName");
        ValidateRequiredValue(options.SenderAddress, $"{EmailOptions.SectionName}:SenderAddress");

        if (!MailboxAddress.TryParse(options.SenderAddress, out _))
        {
            throw new InvalidOperationException(
                $"The configuration value '{EmailOptions.SectionName}:SenderAddress' must be a valid email address.");
        }

        ValidateRequiredValue(options.Username, $"{EmailOptions.SectionName}:Username");
        ValidateRequiredValue(options.Password, $"{EmailOptions.SectionName}:Password");
    }

    private static void ValidateRequiredValue(string value, string configurationName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException(
                $"The configuration value '{configurationName}' is required.");
        }
    }
}