# Install gossan from GitHub Releases into a durable PATH location (Windows).
#
# Copy-paste (PowerShell):
#   irm https://raw.githubusercontent.com/santhreal/gossan/main/scripts/install.ps1 | iex
#
# Env / params:
#   -InstallDir   default: $env:LOCALAPPDATA\gossan\bin
#   -Version      release tag without leading v (default: latest)
#   -Repo         owner/name (default: santhreal/gossan)

[CmdletBinding()]
param(
    [string]$InstallDir = $(if ($env:GOSSAN_INSTALL_DIR) { $env:GOSSAN_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "gossan\bin" }),
    [string]$Version = $(if ($env:GOSSAN_VERSION) { $env:GOSSAN_VERSION } else { "" }),
    [string]$Repo = $(if ($env:GOSSAN_REPO) { $env:GOSSAN_REPO } else { "santhreal/gossan" })
)

$ErrorActionPreference = "Stop"

$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
switch ($arch) {
    "X64" { $target = "x86_64-pc-windows-msvc" }
    "Arm64" {
        Write-Error "No arm64 Windows release asset yet. Build from source or use WSL."
    }
    default { Write-Error "Unsupported architecture: $arch" }
}

$asset = "gossan-$target.zip"
if ($Version) {
    $base = "https://github.com/$Repo/releases/download/v$Version"
} else {
    $base = "https://github.com/$Repo/releases/latest/download"
}

$tmpdir = Join-Path ([System.IO.Path]::GetTempPath()) ("gossan-install-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Path $tmpdir | Out-Null
try {
    $zipPath = Join-Path $tmpdir $asset
    Write-Host "gossan install → $InstallDir"
    Write-Host "  downloading $base/$asset"
    Invoke-WebRequest -Uri "$base/$asset" -OutFile $zipPath

    $shaUrl = "$base/$asset.sha256"
    try {
        $shaPath = Join-Path $tmpdir "$asset.sha256"
        Invoke-WebRequest -Uri $shaUrl -OutFile $shaPath
        $expected = ((Get-Content $shaPath -Raw).Split()[0]).Trim().ToLowerInvariant()
        $actual = (Get-FileHash -Algorithm SHA256 -Path $zipPath).Hash.ToLowerInvariant()
        if ($expected -ne $actual) {
            throw "checksum mismatch: expected $expected got $actual"
        }
        Write-Host "  checksum ok"
    } catch {
        if ($_.Exception.Message -like "checksum mismatch*") { throw }
        Write-Host "  note: no checksum sidecar; skipping verify"
    }

    Expand-Archive -Path $zipPath -DestinationPath $tmpdir -Force
    $bin = Get-ChildItem -Path $tmpdir -Recurse -Filter gossan.exe | Select-Object -First 1
    if (-not $bin) { throw "archive did not contain gossan.exe" }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $dest = Join-Path $InstallDir "gossan.exe"
    Copy-Item -Force $bin.FullName $dest

    & $dest --version | Out-Null
    Write-Host "  ✓ gossan → $dest"

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @()
    if ($userPath) { $parts = $userPath.Split(";") | Where-Object { $_ -ne "" } }
    if ($parts -notcontains $InstallDir) {
        $newPath = if ($userPath) { "$InstallDir;$userPath" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        $env:Path = "$InstallDir;$env:Path"
        Write-Host ""
        Write-Host "PATH updated for your user profile:"
        Write-Host "  $InstallDir"
        Write-Host "Open a new PowerShell window (or refresh PATH) then run:"
        Write-Host "  gossan --version"
    } else {
        Write-Host "PATH already contains $InstallDir"
    }

    Write-Host "done. Try: gossan --version"
}
finally {
    Remove-Item -Recurse -Force $tmpdir -ErrorAction SilentlyContinue
}
