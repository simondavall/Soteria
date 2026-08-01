using Serilog;
using Serilog.Events;

namespace Soteria;

internal static class SoteriaLogging
{
    public const string LogDirectory = @"C:\ProgramData\Soteria\Logs";

    private const long FileSizeLimitBytes = 10 * 1024 * 1024;
    private static readonly TimeSpan RetentionPeriod = TimeSpan.FromDays(14);

    public static void Configure(WebApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        EnsureLogDirectory();

        Log.Logger = CreateLoggerConfiguration()
            .CreateBootstrapLogger();

        builder.Logging.ClearProviders();
        builder.Services.AddSerilog((services, configuration) =>
        {
            ConfigureLogger(configuration)
                .ReadFrom.Services(services);
        });
    }

    private static LoggerConfiguration CreateLoggerConfiguration()
    {
        return ConfigureLogger(new LoggerConfiguration());
    }

    private static LoggerConfiguration ConfigureLogger(
        LoggerConfiguration configuration)
    {
        return configuration
            .MinimumLevel.Information()
            .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
            .MinimumLevel.Override("System", LogEventLevel.Warning)
            .MinimumLevel.Override("Microsoft.EntityFrameworkCore", LogEventLevel.Warning)
            .MinimumLevel.Override("OpenIddict", LogEventLevel.Warning)
            .Enrich.FromLogContext()
            .Enrich.WithProperty("Application", "Soteria")
            .WriteTo.File(
                path: Path.Combine(LogDirectory, "soteria-.log"),
                restrictedToMinimumLevel: LogEventLevel.Information,
                outputTemplate:
                    "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} " +
                    "[{Level:u3}] " +
                    "[{SourceContext}] " +
                    "{Message:lj}" +
                    "{NewLine}{Exception}",
                rollingInterval: RollingInterval.Day,
                fileSizeLimitBytes: FileSizeLimitBytes,
                rollOnFileSizeLimit: true,
                retainedFileCountLimit: null,
                retainedFileTimeLimit: RetentionPeriod,
                shared: false,
                flushToDiskInterval: TimeSpan.FromSeconds(1));
    }

    private static void EnsureLogDirectory()
    {
        try
        {
            Directory.CreateDirectory(LogDirectory);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new InvalidOperationException(
                $"The Production log directory '{LogDirectory}' could not be created or accessed. " +
                "Grant the IIS Application Pool identity Modify permission to the directory.",
                exception);
        }
        catch (IOException exception)
        {
            throw new InvalidOperationException(
                $"The Production log directory '{LogDirectory}' could not be created or accessed.",
                exception);
        }
    }
}