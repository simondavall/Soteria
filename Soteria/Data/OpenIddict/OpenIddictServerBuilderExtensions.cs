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

        var encryptionKey = configuration["OpenIddict:EncryptionKey"];

        if (string.IsNullOrWhiteSpace(encryptionKey))
        {
            throw new InvalidOperationException(
                "Configuration value 'OpenIddict:EncryptionKey' is missing.");
        }

        builder.AddEncryptionKey(new SymmetricSecurityKey(Convert.FromBase64String(encryptionKey)));
    }

    private static void ConfigureProduction(OpenIddictServerBuilder builder, IConfiguration configuration)
    {
        var options = new OpenIddictCertificateOptions();

        configuration
            .GetSection(OpenIddictCertificateOptions.SectionName)
            .Bind(options);

        var signingCertificate = CertificateLoader.LoadSigningCertificate(options);
        var encryptionCertificate = CertificateLoader.LoadEncryptionCertificate(options);

        builder.AddSigningCertificate(signingCertificate);
        builder.AddEncryptionCertificate(encryptionCertificate);
    }
}