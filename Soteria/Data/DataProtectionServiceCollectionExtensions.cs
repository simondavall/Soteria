using Microsoft.AspNetCore.DataProtection;
using System.Security.Cryptography.X509Certificates;

namespace Soteria.Data;

internal static class DataProtectionServiceCollectionExtensions
{
    private const string ApplicationName = "Soteria";

    public static IServiceCollection AddSoteriaDataProtection(
        this IServiceCollection services,
        IWebHostEnvironment environment,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(configuration);

        if (environment.IsDevelopment())
        {
            return services;
        }

        var keysPath = configuration["DataProtection:KeysPath"]
                       ?? throw new InvalidOperationException(
                           "DataProtection:KeysPath is not configured.");

        var certificatePath = configuration["DataProtection:CertificatePath"]
                              ?? throw new InvalidOperationException(
                                  "DataProtection:CertificatePath is not configured.");

        var certificatePassword = configuration["DataProtection:CertificatePassword"]
                                  ?? throw new InvalidOperationException(
                                      "DataProtection:CertificatePassword is not configured.");

        Directory.CreateDirectory(keysPath);

        var certificate = X509CertificateLoader.LoadPkcs12FromFile(
            certificatePath,
            certificatePassword,
            X509KeyStorageFlags.EphemeralKeySet);

        services
            .AddDataProtection()
            .SetApplicationName(ApplicationName)
            .PersistKeysToFileSystem(new DirectoryInfo(keysPath))
            .ProtectKeysWithCertificate(certificate);

        return services;
    }
}