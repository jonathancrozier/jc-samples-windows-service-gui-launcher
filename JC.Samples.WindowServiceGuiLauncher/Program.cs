using JC.Samples.WindowsServiceGuiLauncher;
using JC.Samples.WindowsServiceGuiLauncher.Services;
using JC.Samples.WindowsServiceGuiLauncher.Services.Interfaces;

// Initialise the hosting environment.
IHost host = Host.CreateDefaultBuilder(args)
    .UseWindowsService(options =>
    {
        // Configure the Windows Service Name.
        options.ServiceName = "WindowsServiceGuiLauncher";
    })
    .ConfigureServices(services =>
    {
        // Register the primary worker service.
        services.AddHostedService<Worker>();

        // Register other services here.
        services.AddSingleton<IProcessServices, ProcessServices>();
    })
    .Build();

// Run the application.
await host.RunAsync();