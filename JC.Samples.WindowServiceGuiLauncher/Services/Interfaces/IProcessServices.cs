using System.Diagnostics;

namespace JC.Samples.WindowsServiceGuiLauncher.Services.Interfaces;

/// <summary>
/// Process Services interface.
/// </summary>
public interface IProcessServices
{
    #region Methods

    bool StartProcessAsCurrentUser(
        string processCommandLine,
        string? processWorkingDirectory = null,
        Process? userProcess = null);

    #endregion
}