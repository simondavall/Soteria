using Serilog;
using Serilog.Events;

namespace Soteria.Infrastructure.Logging;

internal static class SoteriaLogging
{
    private const long FileSizeLimitBytes = 10 * 1024 * 1024;
    private static readonly TimeSpan RetentionPeriod = TimeSpan.FromDays(14);

    public static void Configure(WebApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var logDirectory = builder.Configuration["Logging:Directory"];

        if (string.IsNullOrWhiteSpace(logDirectory))
        {
            throw new InvalidOperationException("Production logging configuration 'Logging:Directory' is required.");
        }

        EnsureLogDirectory(logDirectory);

        Log.Logger = CreateLoggerConfiguration(logDirectory)
            .CreateBootstrapLogger();

        builder.Logging.ClearProviders();

        builder.Services.AddSerilog((services, configuration) =>
        {
            ConfigureLogger(configuration, logDirectory)
                .ReadFrom.Services(services);
        });
    }

    private static LoggerConfiguration CreateLoggerConfiguration(string logDirectory)
    {
        return ConfigureLogger(new LoggerConfiguration(), logDirectory);
    }

    private static LoggerConfiguration ConfigureLogger(LoggerConfiguration configuration, string logDirectory)
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
                path: Path.Combine(logDirectory, "soteria-.log"),
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

    private static void EnsureLogDirectory(string logDirectory)
    {
        try
        {
            Directory.CreateDirectory(logDirectory);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new InvalidOperationException(
                $"The Production log directory '{logDirectory}' " +
                "could not be created or accessed. " +
                "Grant the IIS Application Pool identity Modify " +
                "permission to the directory.",
                exception);
        }
        catch (IOException exception)
        {
            throw new InvalidOperationException(
                $"The Production log directory '{logDirectory}' " +
                "could not be created or accessed.",
                exception);
        }
    }
}