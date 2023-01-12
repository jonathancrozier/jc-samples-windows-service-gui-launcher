using JC.Samples.WindowsServiceGuiLauncher.Services.Interfaces;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace JC.Samples.WindowsServiceGuiLauncher.Services;
 
/// <summary>
/// Provides services for launching new processes.
/// </summary>
public class ProcessServices : IProcessServices
{
    #region WIN32
 
    #region Constants
 
    private const uint  CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const int   GENERIC_ALL_ACCESS         = 0x10000000;
    private const int   STARTF_FORCEONFEEDBACK     = 0x00000040;
    private const int   STARTF_USESHOWWINDOW       = 0x00000001;
    private const short SW_SHOW                    = 5;
    private const uint  TOKEN_ASSIGN_PRIMARY       = 0x0001;
    private const uint  TOKEN_DUPLICATE            = 0x0002;
    private const uint  TOKEN_QUERY                = 0x0008;
 
    #endregion
 
    #region Structs
 
    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint   dwProcessId;
        public uint   dwThreadId;
    }
 
    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public uint   nLength;
        public IntPtr lpSecurityDescriptor;
        public bool   bInheritHandle;
    }
 
    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFO
    {
        public uint   cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint   dwX;
        public uint   dwY;
        public uint   dwXSize;
        public uint   dwYSize;
        public uint   dwXCountChars;
        public uint   dwYCountChars;
        public uint   dwFillAttribute;
        public uint   dwFlags;
        public short  wShowWindow;
        public short  cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
 
    #endregion
 
    #region Enums
 
    private enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous      = 0,
        SecurityIdentification = 1,
        SecurityImpersonation  = 2,
        SecurityDelegation     = 3
    }
 
    private enum TOKEN_TYPE
    {
        TokenPrimary       = 1,
        TokenImpersonation = 2
    }
 
    #endregion
 
    #region Imports
 
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(
        IntPtr hObject);
 
    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(
        ref IntPtr lpEnvironment,
        IntPtr     hToken,
        bool       bInherit);
 
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CreateProcessAsUser(
        IntPtr                  hToken,
        string?                 lpApplicationName,
        string?                 lpCommandLine,
        ref SECURITY_ATTRIBUTES lpProcessAttributes,
        ref SECURITY_ATTRIBUTES lpThreadAttributes,
        bool                    bInheritHandles,
        uint                    dwCreationFlags,
        IntPtr                  lpEnvironment,
        string?                 lpCurrentDirectory,
        ref STARTUPINFO         lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);
 
    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(
        IntPtr lpEnvironment);
 
    [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx", SetLastError = true)]
    private static extern bool DuplicateTokenEx(
        IntPtr                       hExistingToken,
        uint                         dwDesiredAccess,
        ref SECURITY_ATTRIBUTES      lpTokenAttributes,
        SECURITY_IMPERSONATION_LEVEL impersonationLevel,
        TOKEN_TYPE                   tokenType,
        ref IntPtr                   phNewToken);
 
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(
        IntPtr     processHandle,
        uint       desiredAccess,
        ref IntPtr tokenHandle);
 
    #endregion
 
    #endregion
 
    #region Readonlys
 
    private readonly ILogger<ProcessServices>? _logger;
 
    #endregion
 
    #region Constructor
 
    /// <summary>
    /// Default Constructor.
    /// </summary>
    public ProcessServices()
    {
    }
 
    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="logger"><see cref="ILogger"/></param>
    public ProcessServices(ILogger<ProcessServices> logger)
    {
        _logger = logger;
    }
 
    #endregion
 
    #region Methods
 
    #region Public
 
    /// <summary>
    /// Starts a process as the currently logged in user.
    /// </summary>
    /// <param name="processCommandLine">The full process command-line</param>
    /// <param name="processWorkingDirectory">The process working directory (optional)</param>
    /// <param name="userProcess">The user process to get the Primary Token from (optional)</param>
    /// <returns>True if the process started successfully, otherwise false</returns>
    public bool StartProcessAsCurrentUser(
        string   processCommandLine, 
        string?  processWorkingDirectory = null, 
        Process? userProcess = null)
    {
        bool success = false;
 
        if (userProcess == null)
        {
            // If a specific user process hasn't been specified, use the explorer process.
            Process[] processes = Process.GetProcessesByName("explorer");
 
            if (processes.Any())
            {
                userProcess = processes[0];
            }
        }
 
        if (userProcess != null)
        {
            IntPtr token = GetPrimaryToken(userProcess);
 
            if (token != IntPtr.Zero)
            {
                IntPtr block = IntPtr.Zero;
 
                try
                {
                    block   = GetEnvironmentBlock(token);
                    success = LaunchProcess(processCommandLine, processWorkingDirectory, token, block);
                }
                finally
                {
                    if (block != IntPtr.Zero)
                    {
                        DestroyEnvironmentBlock(block);
                    }
 
                    CloseHandle(token);
                }
            }
        }
 
        return success;
    }
 
    #endregion
 
    #region Private
 
    /// <summary>
    /// Gets the Environment Block based on the specified token.
    /// </summary>
    /// <param name="token">The token pointer</param>
    /// <returns>The Environment Block pointer</returns>
    private IntPtr GetEnvironmentBlock(IntPtr token)
    {
        IntPtr block  = IntPtr.Zero;
        bool   result = CreateEnvironmentBlock(ref block, token, false);
 
        if (!result)
        {
            _logger?.LogError("CreateEnvironmentBlock Error: {0}", Marshal.GetLastWin32Error());
        }
 
        return block;
    }
 
    /// <summary>
    /// Gets the Primary Token for the specified process.
    /// </summary>
    /// <param name="process">The process to get the token for</param>
    /// <returns>The token pointer</returns>
    private IntPtr GetPrimaryToken(Process process)
    {
        IntPtr primaryToken = IntPtr.Zero;
 
        // Get the impersonation token.
        IntPtr token      = IntPtr.Zero;
        bool   openResult = OpenProcessToken(process.Handle, TOKEN_DUPLICATE, ref token);
 
        if (openResult)
        {
            try
            {
                var securityAttributes     = new SECURITY_ATTRIBUTES();
                securityAttributes.nLength = (uint)Marshal.SizeOf(securityAttributes);
 
                // Convert the impersonation token into a Primary token.
                openResult = DuplicateTokenEx(
                    token,
                    TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
                    ref securityAttributes,
                    SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                    TOKEN_TYPE.TokenPrimary,
                    ref primaryToken);
            }
            finally
            {
                CloseHandle(token);
            }
 
            if (!openResult)
            {
                _logger?.LogError("DuplicateTokenEx Error: {0}", Marshal.GetLastWin32Error());
            }
        }
        else
        {
            _logger?.LogError("OpenProcessToken Error: {0}", Marshal.GetLastWin32Error());
        }
 
        return primaryToken;
    }
 
    /// <summary>
    /// Launches the process as the user indicated by the token and Environment Block.
    /// </summary>
    /// <param name="commandLine">The full process command-line</param>
    /// <param name="workingDirectory">The process working directory</param>
    /// <param name="token">The token pointer</param>
    /// <param name="environmentBlock">The Environment Block pointer</param>
    /// <returns>True if the process was launched successfully, otherwise false</returns>
    private bool LaunchProcess(
        string  commandLine, 
        string? workingDirectory, 
        IntPtr  token, 
        IntPtr  environmentBlock)
    {
        var startupInfo = new STARTUPINFO();
        startupInfo.cb  = (uint)Marshal.SizeOf(startupInfo);
 
        // If 'lpDesktop' is NULL, the new process will inherit the desktop and window station of its parent process.
        // If it is an empty string, the process does not inherit the desktop and window station of its parent process; 
        // instead, the system determines if a new desktop and window station need to be created.
        // If the impersonated user already has a desktop, the system uses the existing desktop.
        startupInfo.lpDesktop   = @"WinSta0\Default"; // Modify as needed.
        startupInfo.dwFlags     = STARTF_USESHOWWINDOW | STARTF_FORCEONFEEDBACK;
        startupInfo.wShowWindow = SW_SHOW;
 
        var processSecurityAttributes     = new SECURITY_ATTRIBUTES();
        processSecurityAttributes.nLength = (uint)Marshal.SizeOf(processSecurityAttributes);
 
        var threadSecurityAttributes     = new SECURITY_ATTRIBUTES();
        threadSecurityAttributes.nLength = (uint)Marshal.SizeOf(threadSecurityAttributes);
 
        bool result = CreateProcessAsUser(
            token,
            null,
            commandLine,
            ref processSecurityAttributes,
            ref threadSecurityAttributes,
            false,
            CREATE_UNICODE_ENVIRONMENT,
            environmentBlock,
            workingDirectory,
            ref startupInfo,
            out _);
 
        if (!result)
        {
            _logger?.LogError("CreateProcessAsUser Error: {0}", Marshal.GetLastWin32Error());
        }
 
        return result;
    }
 
    #endregion
 
    #endregion
}