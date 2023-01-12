using JC.Samples.WindowsServiceGuiLauncher.Services;
using JC.Samples.WindowsServiceGuiLauncher.Services.Interfaces;

namespace JC.Samples.WindowsServiceGuiLauncher;

/// <summary>
/// The main Worker Service.
/// </summary>
public class Worker : BackgroundService
{
    #region Readonlys

    private readonly ILogger<Worker>  _logger;
    private readonly IProcessServices _processServices;

    #endregion

    #region Constructor

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="logger"><see cref="ILogger"/></param>
    /// <param name="processServices"><see cref="IProcessServices"/></param>
    public Worker(ILogger<Worker> logger, IProcessServices processServices)
    {
        _logger          = logger;
        _processServices = processServices;
    }

    #endregion

    #region Methods

    /// <summary>
    /// Executes when the service has started.
    /// </summary>
    /// <param name="stoppingToken"><see cref="CancellationToken"/></param>
    /// <returns><see cref="Task"/></returns>
    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            _logger.LogInformation("** SERVICE STARTED **");

            if (!stoppingToken.IsCancellationRequested)
            {
                _logger.LogInformation("Starting Notepad");

                _processServices.StartProcessAsCurrentUser("notepad");

                _logger.LogInformation("Notepad started");
            }

            return Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, ex.Message);
            throw;
        }
    }

    /// <summary>
    /// Executes when the service is ready to start.
    /// </summary>
    /// <param name="cancellationToken"><see cref="CancellationToken"/></param>
    /// <returns><see cref="Task"/></returns>
    public override Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Starting service");

        return base.StartAsync(cancellationToken);
    }

    /// <summary>
    /// Executes when the service is performing a graceful shutdown.
    /// </summary>
    /// <param name="cancellationToken"><see cref="CancellationToken"/></param>
    /// <returns><see cref="Task"/></returns>
    public override Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Stopping service");

        return base.StopAsync(cancellationToken);
    }

    #endregion
}