[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'dist/bitwardenxc-cli'),
    [string]$WorkDirectory = (Join-Path ([IO.Path]::GetTempPath()) 'bitwardenxc-cli-2026.10.1-build')
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$revision = '91214c3b978edb5496a32a946451960fe7d44531' # Bitwarden clients cli-v2026.10.1
$expectedVersion = '2026.10.1-bitwardenxc.1'
$nodeVersion = '22.23.5'
$npmVersion = '11.18.0'
$pkgVersion = '3.5'
$pkgNodeVersion = '22.15.1'
$patch = Join-Path $PSScriptRoot 'bitwardenxc-cli-v2026.10.1.patch'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    throw 'The BitwardenXC companion CLI build requires Windows x64.'
}
$git = (Get-Command git.exe -ErrorAction Stop).Source
$tar = (Get-Command tar.exe -ErrorAction Stop).Source

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)

    # Windows PowerShell can turn native stderr, including progress, into errors.
    $ErrorActionPreference = 'Continue'
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$(Split-Path -Leaf $Program) failed (exit code $LASTEXITCODE)."
    }
}

function Test-Git {
    param([string[]]$Arguments)

    $ErrorActionPreference = 'Continue'
    & $git -C $source @Arguments 2>$null | Out-Null
    return $LASTEXITCODE -eq 0
}

function Get-VerifiedFile {
    param([string]$Uri, [string]$File, [string]$Digest, [string]$Algorithm = 'SHA256')

    if ((Test-Path -LiteralPath $File) -and (Get-FileHash -LiteralPath $File -Algorithm $Algorithm).Hash -eq $Digest) {
        return
    }

    $partial = "$File.partial"
    Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $partial
    if ((Get-FileHash -LiteralPath $partial -Algorithm $Algorithm).Hash -ne $Digest) {
        throw "Checksum mismatch for $(Split-Path -Leaf $File)."
    }
    Move-Item -LiteralPath $partial -Destination $File -Force
}

$work = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($WorkDirectory)
$targetDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
$source = Join-Path $work 'clients'
$tools = Join-Path $work 'tools'
$node = Join-Path $tools "node-v$nodeVersion-win-x64"
$npmDirectory = Join-Path $tools "npm-$npmVersion"
$npm = Join-Path $npmDirectory 'package/bin/npm-cli.js'
$pkgCache = Join-Path $tools 'pkg-cache'
$pkgVersionDirectory = Join-Path $pkgCache "v$pkgVersion"
New-Item -ItemType Directory -Force -Path $tools, $npmDirectory, $pkgVersionDirectory | Out-Null

if (-not (Test-Path -LiteralPath (Join-Path $source '.git'))) {
    if ((Test-Path -LiteralPath $source) -and (Get-ChildItem -LiteralPath $source -Force | Select-Object -First 1)) {
        throw "The companion source directory must be empty: $source"
    }
    Invoke-Checked $git @('init', '--quiet', $source)
}
if (-not (Test-Git @('rev-parse', '--verify', 'HEAD'))) {
    Invoke-Checked $git @('-C', $source, 'fetch', '--depth=1', '--no-tags',
        'https://github.com/bitwarden/clients.git', $revision)
    Invoke-Checked $git @('-C', $source, '-c', 'core.autocrlf=false', 'checkout', '--detach', '--quiet', 'FETCH_HEAD')
}
$head = Invoke-Checked $git @('-C', $source, 'rev-parse', 'HEAD')
if ($head -ne $revision) {
    throw "Expected Bitwarden clients commit $revision in $source."
}

if (-not (Test-Git @('apply', '--reverse', '--check', $patch))) {
    Invoke-Checked $git @('-C', $source, 'apply', '--check', $patch)
    Invoke-Checked $git @('-C', $source, 'apply', $patch)
}
Invoke-Checked $git @('-C', $source, 'diff', '--check')

$nodeZip = Join-Path $tools "node-v$nodeVersion-win-x64.zip"
$nodeDigest = '4a191082e9706866830379d577d2cc8a50c776fcd9436a8d061b063ed0d9a0e3'
Get-VerifiedFile "https://nodejs.org/dist/v$nodeVersion/node-v$nodeVersion-win-x64.zip" $nodeZip $nodeDigest
$nodeExe = Join-Path $node 'node.exe'
if (-not (Test-Path -LiteralPath $nodeExe)) {
    Expand-Archive -LiteralPath $nodeZip -DestinationPath $tools -Force
}

$npmArchive = Join-Path $tools "npm-$npmVersion.tgz"
$npmDigest = '4faecce0be70366d1c67b1012c4adc1246354a6cc45bf589f92003073b05518d547403df1475c542d67a4845e22b4fafcd7cac0af02c7a96cc6814f09eb003fb'
Get-VerifiedFile "https://registry.npmjs.org/npm/-/npm-$npmVersion.tgz" $npmArchive $npmDigest SHA512
if (-not (Test-Path -LiteralPath $npm)) {
    Invoke-Checked $tar @('-xzf', $npmArchive, '-C', $npmDirectory)
}

$pkgRuntime = Join-Path $pkgVersionDirectory "fetched-v$pkgNodeVersion-win-x64"
$pkgRuntimeUrl = "https://github.com/yao-pkg/pkg-fetch/releases/download/v$pkgVersion/node-v$pkgNodeVersion-win-x64"
Get-VerifiedFile $pkgRuntimeUrl $pkgRuntime 'fd78dc295241575f07a545385915bdf238d4fa9972679a984c5f82cd8361f005'

$userNpmConfig = Join-Path $tools 'user.npmrc'
$globalNpmConfig = Join-Path $tools 'global.npmrc'
Set-Content -LiteralPath $userNpmConfig -Value '' -Encoding ASCII
Set-Content -LiteralPath $globalNpmConfig -Value '' -Encoding ASCII
$cliProfile = Join-Path $work 'smoke-profile'
New-Item -ItemType Directory -Force -Path $cliProfile | Out-Null

$oldEnvironment = @{}
$buildEnvironment = @{
    PATH = "$node;$env:PATH"
    PKG_CACHE_PATH = $pkgCache
    npm_config_cache = (Join-Path $tools 'npm-cache')
    npm_config_userconfig = $userNpmConfig
    npm_config_globalconfig = $globalNpmConfig
    BITWARDENCLI_APPDATA_DIR = $cliProfile
    BW_SESSION = $null
    BW_CLIENTID = $null
    BW_CLIENTSECRET = $null
    NODE_OPTIONS = $null
    NODE_PATH = $null
}
foreach ($key in $buildEnvironment.Keys) {
    $oldEnvironment[$key] = [Environment]::GetEnvironmentVariable($key)
    [Environment]::SetEnvironmentVariable($key, $buildEnvironment[$key])
}

Push-Location -LiteralPath $source
try {
    Invoke-Checked $nodeExe @($npm, 'ci', '--no-audit', '--no-fund')

    # Keep the upstream OSS build independent of commercially licensed modules.
    $modules = [IO.Path]::GetFullPath((Join-Path $source 'node_modules'))
    $scopeDirectory = Join-Path $modules '@bitwarden'
    $commercial = Join-Path $scopeDirectory 'commercial-sdk-internal'
    if (Test-Path -LiteralPath $commercial) {
        foreach ($directory in @($source, $modules, $scopeDirectory)) {
            if ((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'A directory in the commercial SDK path is a symbolic link.'
            }
        }
        $package = Get-Item -LiteralPath $commercial -Force
        if (-not $package.FullName.StartsWith("$modules\", [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The commercial SDK path is outside the build dependency directory.'
        }
        if ($package.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            Remove-Item -LiteralPath $package.FullName -Force
        } else {
            Remove-Item -LiteralPath $package.FullName -Recurse -Force
        }
    }

    Invoke-Checked $nodeExe @($npm, 'test', '--', '--runInBand', '--runTestsByPath',
        'libs/common/src/models/export/cipher.export.spec.ts')
    # Run the three upstream dist:oss:win steps with the same pinned npm.
    foreach ($task in @('build:oss:prod', 'clean', 'package:oss:win')) {
        Invoke-Checked $nodeExe @($npm, 'run', $task, '--workspace', '@bitwarden/cli')
    }

    $executable = Join-Path $source 'apps/cli/dist/oss/windows/bw.exe'
    $version = Invoke-Checked $executable @('--version')
    if (($version | Out-String).Trim() -ne $expectedVersion) {
        throw "The companion CLI did not report $expectedVersion."
    }

    New-Item -ItemType Directory -Force -Path $targetDirectory | Out-Null
    $output = Join-Path $targetDirectory 'bw.exe'
    Copy-Item -LiteralPath $executable -Destination $output -Force
    Write-Output "BitwardenXC CLI $expectedVersion built at $output"
} finally {
    Pop-Location
    foreach ($key in $oldEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($key, $oldEnvironment[$key])
    }
}
