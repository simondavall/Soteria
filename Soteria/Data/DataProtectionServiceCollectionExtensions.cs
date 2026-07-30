using Microsoft.AspNetCore.DataProtection;

namespace Soteria.Data;

internal static class DataProtectionServiceCollectionExtensions
{
    private const string ApplicationName = "Soteria";
    private const string ProductionKeyRingPath =
        @"C:\ProgramData\Soteria\DataProtection";

    public static IServiceCollection AddSoteriaDataProtection(this IServiceCollection services, IWebHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(environment);

        if (environment.IsDevelopment())
        {
            return services;
        }

        Directory.CreateDirectory(ProductionKeyRingPath);

        services
            .AddDataProtection()
            .SetApplicationName(ApplicationName)
            .PersistKeysToFileSystem(new DirectoryInfo(ProductionKeyRingPath))
            .ProtectKeysWithDpapi(protectToLocalMachine: true);

        return services;
    }
}