using Microsoft.IdentityModel.Tokens;

namespace Soteria.Data.OpenIddict;

internal static class OpenIddictServerBuilderExtensions
{
    public static OpenIddictServerBuilder AddSoteriaCredentials(this OpenIddictServerBuilder builder, IWebHostEnvironment environment,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(configuration);

        if (environment.IsDevelopment())
        {
            ConfigureDevelopment(builder, configuration);
        }
        else
        {
            ConfigureProduction(builder, configuration);
        }

        return builder;
    }

    private static void ConfigureDevelopment(OpenIddictServerBuilder builder, IConfiguration configuration)
    {
        builder.AddDevelopmentSigningCertificate();

        var configuredEncryptionKey = configuration["OpenIddict:EncryptionKey"];
        if (string.IsNullOrWhiteSpace(configuredEncryptionKey))
        {
            throw new InvalidOperationException(
                "The Development configuration value 'OpenIddict:EncryptionKey' is required.");
        }

        byte[] encryptionKey;

        try
        {
            encryptionKey = Convert.FromBase64String(configuredEncryptionKey.Trim());
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException(
                "The Development configuration value " +
                "'OpenIddict:EncryptionKey' must be a valid Base64 value.",
                exception);
        }

        if (encryptionKey.Length < 32)
        {
            throw new InvalidOperationException(
                "The Development configuration value " +
                "'OpenIddict:EncryptionKey' must contain at least " +
                "256 bits of key material.");
        }

        builder.AddEncryptionKey(new SymmetricSecurityKey(encryptionKey));
    }

    private static void ConfigureProduction(OpenIddictServerBuilder builder, IConfiguration configuration)
    {
        var options = new OpenIddictCertificateOptions();

        configuration
            .GetSection(OpenIddictCertificateOptions.SectionName)
            .Bind(options);

        var signingCertificate = CertificateLoader.LoadSigningCertificate(options);
        var encryptionCertificate = CertificateLoader.LoadEncryptionCertificate(options);

        if (string.Equals(signingCertificate.Thumbprint, encryptionCertificate.Thumbprint, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The OpenIddict signing and encryption certificates must be different certificates.");
        }

        builder.AddSigningCertificate(signingCertificate);
        builder.AddEncryptionCertificate(encryptionCertificate);
    }
}