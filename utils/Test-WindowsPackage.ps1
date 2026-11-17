#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Executable,

    [ValidateRange(1, 60)]
    [int]$TimeoutSeconds = 15
)

$ErrorActionPreference = 'Stop'
$app = Get-Item -LiteralPath $Executable
$temporaryDirectory = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$testDirectory = Join-Path $temporaryDirectory ('bitwardenxc-package-gui-' + [guid]::NewGuid().ToString('N'))
$process = $null
$stdout = $null
$stderr = $null
$failure = $null
$diagnostics = ''

if (-not ('BitwardenXCPackageSmoke.NativeWindows' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace BitwardenXCPackageSmoke
{
    public static class NativeWindows
    {
        private delegate bool EnumWindowsCallback(IntPtr window, IntPtr state);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsCallback callback, IntPtr state);
        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowText(IntPtr window, StringBuilder text, int capacity);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetClassName(IntPtr window, StringBuilder text, int capacity);
        [DllImport("user32.dll")]
        private static extern IntPtr SendMessageTimeout(IntPtr window, uint message, IntPtr wParam,
            IntPtr lParam, uint flags, uint timeout, out IntPtr result);

        public static IntPtr FindMainWindow(int processId)
        {
            IntPtr found = IntPtr.Zero;
            // Process.MainWindowHandle excludes windows hidden by the startup options.
            EnumWindows((window, state) => {
                uint owner;
                GetWindowThreadProcessId(window, out owner);
                if (owner != (uint)processId) {
                    return true;
                }
                var title = new StringBuilder(256);
                var className = new StringBuilder(256);
                GetWindowText(window, title, title.Capacity);
                GetClassName(window, className, className.Capacity);
                if (title.ToString() == "BitwardenXC" && className.ToString().StartsWith("Qt")
                    && className.ToString().EndsWith("QWindowIcon")) {
                    found = window;
                    return false;
                }
                return true;
            }, IntPtr.Zero);
            return found;
        }

        public static bool IsResponsive(IntPtr window)
        {
            IntPtr result;
            return SendMessageTimeout(window, 0, IntPtr.Zero, IntPtr.Zero, 2, 1000, out result) != IntPtr.Zero;
        }
    }
}
'@
}

try {
    New-Item -ItemType Directory -Path $testDirectory | Out-Null
    $config = Join-Path $testDirectory 'settings.ini'
    $localConfig = Join-Path $testDirectory 'local.ini'
    @'
[General]
UpdateCheckMessageShown=true
RememberLastDatabases=false
OpenPreviousDatabasesOnStartup=false
[GUI]
CheckForUpdates=false
MinimizeOnStartup=false
ShowTrayIcon=false
'@ | Set-Content -LiteralPath $config -Encoding utf8
    Set-Content -LiteralPath $localConfig -Value '' -Encoding utf8

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $app.FullName
    $startInfo.WorkingDirectory = $app.DirectoryName
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @('--config', $config, '--localconfig', $localConfig)) {
        $startInfo.ArgumentList.Add($argument)
    }

    # Only packaged Qt libraries and plugins may satisfy the GUI startup check.
    $startInfo.Environment['PATH'] = "$env:SystemRoot\System32;$env:SystemRoot"
    foreach ($name in @($startInfo.Environment.Keys)) {
        if ($name.StartsWith('QT_', [System.StringComparison]::OrdinalIgnoreCase) -or
            $name -in @('QML_IMPORT_PATH', 'QML2_IMPORT_PATH', 'KPXC_CONFIG', 'KPXC_CONFIG_LOCAL')) {
            $null = $startInfo.Environment.Remove($name)
        }
    }
    $startInfo.Environment['TEMP'] = $testDirectory
    $startInfo.Environment['TMP'] = $testDirectory
    $startInfo.Environment['QT_QPA_PLATFORM'] = 'windows'
    $startInfo.Environment['QT_DEBUG_PLUGINS'] = '1'
    $startInfo.Environment['QT_LOGGING_TO_CONSOLE'] = '1'
    $startInfo.Environment['QT_COMMAND_LINE_PARSER_NO_GUI_MESSAGE_BOXES'] = '1'

    $process = [System.Diagnostics.Process]::Start($startInfo)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $deadline = [System.Diagnostics.Stopwatch]::StartNew()
    $mainWindow = [IntPtr]::Zero
    while ($deadline.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $process.Refresh()
        if ($process.HasExited) {
            throw "The packaged GUI exited before opening its main window. Exit code $($process.ExitCode)."
        }
        $mainWindow = [BitwardenXCPackageSmoke.NativeWindows]::FindMainWindow($process.Id)
        if ($mainWindow -ne [IntPtr]::Zero) {
            break
        }
        Start-Sleep -Milliseconds 100
    }
    if ($mainWindow -eq [IntPtr]::Zero) {
        throw "The packaged GUI did not open a BitwardenXC main window within $TimeoutSeconds seconds."
    }

    # Let deferred initialization run, including the update-check timer and first paint.
    Start-Sleep -Seconds 1
    $process.Refresh()
    if ($process.HasExited -or -not [BitwardenXCPackageSmoke.NativeWindows]::IsResponsive($mainWindow)) {
        throw 'The packaged GUI stopped responding after creating its main window.'
    }
} catch {
    $failure = $_
} finally {
    if ($process) {
        if (-not $process.HasExited) {
            $null = $process.CloseMainWindow()
            if (-not $process.WaitForExit(5000)) {
                $process.Kill()
                $process.WaitForExit()
            }
        }
        if ($stderr) {
            $diagnostics = $stderr.GetAwaiter().GetResult()
        }
        if ($stdout) {
            $null = $stdout.GetAwaiter().GetResult()
        }
        $process.Dispose()
    }
    # The directory is generated above and must remain a child of the temporary directory.
    $resolvedTestDirectory = [System.IO.Path]::GetFullPath($testDirectory)
    if (-not $resolvedTestDirectory.StartsWith($temporaryDirectory, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The GUI test directory is outside the temporary directory.'
    }
    if (Test-Path -LiteralPath $resolvedTestDirectory) {
        Remove-Item -LiteralPath $resolvedTestDirectory -Recurse -Force
    }
}

if ($failure) {
    throw "$($failure.Exception.Message)`nQt plugin diagnostics`n$diagnostics"
}
Write-Output "Packaged Windows GUI opened and remained responsive: $($app.FullName)"
