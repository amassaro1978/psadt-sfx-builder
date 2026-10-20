#requires -Version 5.1
<#
.SYNOPSIS
    Builds and signs a 7-Zip self-extracting PSADT installer.
.DESCRIPTION
    Packages a trusted PSADT folder into FTP-VendorAppName-Version.exe. The
    embedded launcher relaunches itself in native 64-bit Windows PowerShell on
    64-bit Windows before elevation and PSADT execution, avoiding accidental
    WOW6432 registry redirection.
#>

[CmdletBinding()]
param()

# Windows PowerShell 5.1's WPF host and event pipeline use lazily initialized
# internal script variables (for example, PipelineComplete). StrictMode at the
# GUI scope can turn those framework details into startup exceptions. The
# generated elevated launcher enables StrictMode in its own isolated scope.
Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms

$script:ToolName = 'PSADT SFX Builder'
$script:ToolVersion = '1.0.3'
$script:SelectedCertificate = $null
$script:DetectedEntryScript = $null

# Build-station configuration. Update the SFX path once for your environment;
# these implementation details are intentionally not exposed in the GUI.
$script:SfxModulePath = 'C:\Program Files\7-Zip\7zSD.sfx'
$script:TimestampServer = 'http://timestamp.digicert.com'

function Get-NativeProgramFiles {
    $native = [Environment]::GetEnvironmentVariable('ProgramW6432')
    if ([string]::IsNullOrWhiteSpace($native)) {
        $native = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    }
    return $native
}

function Find-SevenZipExecutable {
    $programFileRoots = @(
        (Get-NativeProgramFiles),
        ${env:ProgramFiles},
        ${env:ProgramFiles(x86)}
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

    foreach ($programFiles in $programFileRoots) {
        $candidate = Join-Path (Join-Path $programFiles '7-Zip') '7z.exe'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    return $null
}

function Test-CodeSigningCertificate {
    param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    if (-not $Certificate.HasPrivateKey) { return $false }
    if ($Certificate.NotBefore -gt (Get-Date) -or $Certificate.NotAfter -le (Get-Date)) { return $false }

    $ekuExtension = $Certificate.Extensions |
        Where-Object { $_.Oid.Value -eq '2.5.29.37' } |
        Select-Object -First 1
    if (-not $ekuExtension) { return $false }

    $eku = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($ekuExtension, $ekuExtension.Critical)
    return [bool]($eku.EnhancedKeyUsages | Where-Object { $_.Value -eq '1.3.6.1.5.5.7.3.3' })
}

function Get-CodeSigningCertificates {
    $results = @()
    foreach ($storePath in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
        if (-not (Test-Path $storePath)) { continue }
        foreach ($cert in @(Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue)) {
            if (-not (Test-CodeSigningCertificate -Certificate $cert)) { continue }
            $results += [pscustomobject]@{
                Display = '{0} | expires {1:yyyy-MM-dd} | {2}… | {3}' -f `
                    $cert.Subject, $cert.NotAfter, $cert.Thumbprint.Substring(0, 10), $storePath
                Certificate = $cert
            }
        }
    }
    return @($results | Sort-Object { $_.Certificate.NotAfter } -Descending)
}

function ConvertTo-SafeFilePart {
    param([AllowEmptyString()][string]$Value)

    $safe = ($Value -replace '\s+', '')
    $safe = $safe -replace '[^A-Za-z0-9._-]', ''
    return $safe.Trim([char[]]@('.', '-', '_'))
}

function Get-CanonicalPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Test-PathWithin {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$Parent
    )

    $candidateFull = (Get-CanonicalPath $Candidate) + '\'
    $parentFull = (Get-CanonicalPath $Parent) + '\'
    return $candidateFull.StartsWith($parentFull, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-PsadtMetadataValue {
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][string]$AssignmentName,
        [Parameter(Mandatory = $true)][string[]]$HeaderLabels
    )

    # Supports both PSADT 3 variables ($appVendor = '...') and PSADT 4
    # hashtable properties (AppVendor = '...') without executing package code.
    $assignmentPattern = '(?im)^\s*\$?' + [regex]::Escape($AssignmentName) + '\s*=\s*[''"](?<value>[^''"]*)[''"]'
    $match = [regex]::Match($Content, $assignmentPattern)
    if ($match.Success -and -not [string]::IsNullOrWhiteSpace($match.Groups['value'].Value)) {
        return $match.Groups['value'].Value.Trim()
    }

    # Also accepts common comment-header forms such as:
    #   - App Vendor: Google
    foreach ($label in $HeaderLabels) {
        $headerPattern = '(?im)^\s*(?:#\s*)?[-*]?\s*' + [regex]::Escape($label) + '\s*:\s*(?<value>[^\r\n]+?)\s*$'
        $match = [regex]::Match($Content, $headerPattern)
        if ($match.Success -and -not [string]::IsNullOrWhiteSpace($match.Groups['value'].Value)) {
            return $match.Groups['value'].Value.Trim()
        }
    }

    return ''
}

function Get-PsadtPackageInfo {
    param([Parameter(Mandatory = $true)][string]$PackagePath)

    if (-not (Test-Path -LiteralPath $PackagePath -PathType Container)) {
        throw "PSADT package folder not found: $PackagePath"
    }

    $rootScripts = @(Get-ChildItem -LiteralPath $PackagePath -Filter '*.ps1' -File -ErrorAction Stop)
    $entryScript = $rootScripts |
        Where-Object { $_.Name -eq 'Invoke-AppDeployToolkit.ps1' } |
        Select-Object -First 1

    if (-not $entryScript) {
        $entryScript = $rootScripts |
            Where-Object {
                $content = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction Stop
                $content -match 'Open-ADTSession' -and $content -match 'Install-ADTDeployment'
            } |
            Select-Object -First 1
    }
    if (-not $entryScript -and $rootScripts.Count -eq 1) {
        $entryScript = $rootScripts[0]
    }
    if (-not $entryScript) {
        throw 'Could not identify the PSADT entry script in the package root.'
    }

    $content = Get-Content -LiteralPath $entryScript.FullName -Raw -ErrorAction Stop
    $metadata = @{}
    $metadata.AppVendor = Get-PsadtMetadataValue -Content $content -AssignmentName 'AppVendor' -HeaderLabels @('App Vendor', 'Application Vendor')
    $metadata.AppName = Get-PsadtMetadataValue -Content $content -AssignmentName 'AppName' -HeaderLabels @('App Name', 'Application Name')
    $metadata.AppVersion = Get-PsadtMetadataValue -Content $content -AssignmentName 'AppVersion' -HeaderLabels @('App Version', 'Application Version')

    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($entryScript.Name)
    if ($baseName -eq 'Invoke-AppDeployToolkit') {
        $rootExe = Get-ChildItem -LiteralPath $PackagePath -Filter '*.exe' -File -ErrorAction Stop |
            Where-Object { $_.Name -notmatch '^(?i)(ServiceUI|Invoke-AppDeployToolkit)\.exe$' } |
            Select-Object -First 1
        if ($rootExe) { $baseName = [System.IO.Path]::GetFileNameWithoutExtension($rootExe.Name) }
    }

    if ([string]::IsNullOrWhiteSpace($metadata.AppVersion) -and
        $baseName -match '^(?<name>.+)-(?<version>\d+(?:\.\d+)+(?:[-+._A-Za-z0-9]*)?)$') {
        $metadata.AppVersion = $Matches.version
        if ([string]::IsNullOrWhiteSpace($metadata.AppName)) { $metadata.AppName = $Matches.name }
    }
    if ([string]::IsNullOrWhiteSpace($metadata.AppName) -and $baseName -ne 'Invoke-AppDeployToolkit') {
        $metadata.AppName = $baseName
    }

    return [pscustomobject]@{
        Vendor          = [string]$metadata.AppVendor
        AppName         = [string]$metadata.AppName
        Version         = [string]$metadata.AppVersion
        EntryScriptName = $entryScript.Name
        EntryScriptPath = $entryScript.FullName
    }
}

function New-SfxLauncherContent {
    param([Parameter(Mandatory = $true)][string]$EntryScriptName)

    $escapedEntry = $EntryScriptName.Replace("'", "''")
    return @"
#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]`$NativeRelaunch,
    [switch]`$Elevated
)

Set-StrictMode -Version 2.0
`$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    `$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    `$principal = New-Object Security.Principal.WindowsPrincipal(`$identity)
    return `$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# A 32-bit SFX can resolve System32 to SysWOW64. Relaunch this bootstrap
# through Sysnative before elevation so PSADT and native PowerShell registry
# commands use the 64-bit registry view on 64-bit Windows.
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    `$nativePowerShell = Join-Path `$env:WINDIR 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath `$nativePowerShell -PathType Leaf)) {
        throw "Native 64-bit Windows PowerShell was not found at [`$nativePowerShell]."
    }
    & `$nativePowerShell -NoProfile -ExecutionPolicy Bypass -File `$PSCommandPath -NativeRelaunch
    exit `$LASTEXITCODE
}

`$currentPowerShell = Join-Path `$PSHOME 'powershell.exe'
if (-not (Test-IsAdministrator)) {
    `$argumentList = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Elevated' -f `$PSCommandPath.Replace('"', '\"')
    `$process = Start-Process -FilePath `$currentPowerShell -ArgumentList `$argumentList -Verb RunAs -WindowStyle Hidden -Wait -PassThru
    exit `$process.ExitCode
}

`$entryScript = Join-Path `$PSScriptRoot '$escapedEntry'
if (-not (Test-Path -LiteralPath `$entryScript -PathType Leaf)) {
    throw "PSADT entry script was not found: `$entryScript"
}

Set-Location -LiteralPath `$PSScriptRoot
& `$entryScript -DeploymentType Install -DeployMode Interactive
`$lastExitCodeVariable = Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
if (`$lastExitCodeVariable -and `$null -ne `$lastExitCodeVariable.Value) {
    exit [int]`$lastExitCodeVariable.Value
}
exit 0
"@
}

function Assert-NoReparsePoints {
    param([Parameter(Mandatory = $true)][string]$RootPath)

    $root = Get-Item -LiteralPath $RootPath -Force -ErrorAction Stop
    if (($root.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Reparse points are not supported: $($root.FullName)"
    }

    $directories = New-Object 'System.Collections.Generic.Stack[System.IO.DirectoryInfo]'
    $directories.Push([System.IO.DirectoryInfo]$root)
    while ($directories.Count -gt 0) {
        $directory = $directories.Pop()
        foreach ($child in @(Get-ChildItem -LiteralPath $directory.FullName -Force -ErrorAction Stop)) {
            if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse points are not supported: $($child.FullName)"
            }
            if ($child.PSIsContainer) {
                $directories.Push([System.IO.DirectoryInfo]$child)
            }
        }
    }
}

function Assert-DirectoryChainHasNoReparsePoint {
    param([Parameter(Mandatory = $true)][string]$Path)

    $directory = [System.IO.DirectoryInfo](Get-Item -LiteralPath $Path -Force -ErrorAction Stop)
    while ($directory) {
        if (($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The output path traverses a reparse point: $($directory.FullName)"
        }
        $directory = $directory.Parent
    }
}

function Write-Utf8WithoutBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Join-BinaryFiles {
    param(
        [Parameter(Mandatory = $true)][string[]]$InputPaths,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    $output = New-Object System.IO.FileStream($OutputPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $buffer = New-Object byte[] (1024 * 1024)
        foreach ($inputPath in $InputPaths) {
            $input = New-Object System.IO.FileStream($inputPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            try {
                while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $output.Write($buffer, 0, $read)
                }
            } finally {
                $input.Dispose()
            }
        }
    } finally {
        $output.Dispose()
    }
}

function Invoke-SevenZipArchive {
    param(
        [Parameter(Mandatory = $true)][string]$SevenZipPath,
        [Parameter(Mandatory = $true)][string]$StagingPath,
        [Parameter(Mandatory = $true)][string]$ArchivePath
    )

    $sourceWildcard = Join-Path $StagingPath '*'
    $output = & $SevenZipPath 'a' '-t7z' $ArchivePath $sourceWildcard '-mx=9' '-m0=LZMA2' '-mmt=on' '-y' 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "7-Zip failed with exit code $LASTEXITCODE.`r`n$($output -join "`r`n")"
    }
    return @($output)
}

function Test-SevenZipPayload {
    param(
        [Parameter(Mandatory = $true)][string]$SevenZipPath,
        [Parameter(Mandatory = $true)][string]$ArchivePath
    )

    $output = & $SevenZipPath 't' $ArchivePath '-y' 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "7-Zip integrity testing failed with exit code $LASTEXITCODE.`r`n$($output -join "`r`n")"
    }
}

function Publish-VerifiedFile {
    param(
        [Parameter(Mandatory = $true)][string]$CandidatePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    $backupPath = $null
    try {
        if (Test-Path -LiteralPath $DestinationPath -PathType Leaf) {
            $backupPath = "$DestinationPath.backup.$([guid]::NewGuid().ToString('N'))"
            Move-Item -LiteralPath $DestinationPath -Destination $backupPath -Force -ErrorAction Stop
        }

        try {
            Move-Item -LiteralPath $CandidatePath -Destination $DestinationPath -Force -ErrorAction Stop
        } catch {
            if ($backupPath -and (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
                Move-Item -LiteralPath $backupPath -Destination $DestinationPath -Force -ErrorAction SilentlyContinue
            }
            throw
        }

        if ($backupPath -and (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
            Remove-Item -LiteralPath $backupPath -Force -ErrorAction Stop
        }
    } catch {
        if ($backupPath -and (Test-Path -LiteralPath $backupPath -PathType Leaf) -and
            -not (Test-Path -LiteralPath $DestinationPath -PathType Leaf)) {
            Move-Item -LiteralPath $backupPath -Destination $DestinationPath -Force -ErrorAction SilentlyContinue
        }
        throw
    }
}

function New-PsadtSfx {
    param(
        [Parameter(Mandatory = $true)][string]$PackagePath,
        [Parameter(Mandatory = $true)][string]$Vendor,
        [Parameter(Mandatory = $true)][string]$AppName,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$EntryScriptName,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$SevenZipPath,
        [Parameter(Mandatory = $true)][string]$SfxModulePath,
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][string]$TimestampServer,
        [scriptblock]$Log
    )

    if (-not (Test-Path -LiteralPath $SevenZipPath -PathType Leaf)) { throw "7z.exe not found: $SevenZipPath" }
    if (-not (Test-Path -LiteralPath $SfxModulePath -PathType Leaf)) { throw "7-Zip SFX module not found: $SfxModulePath" }
    $sfxModuleName = [System.IO.Path]::GetFileName($SfxModulePath)
    if ($sfxModuleName -notin @('7zSD.sfx', '7zS2.sfx', '7zS.sfx')) {
        throw "Unsupported SFX module '$sfxModuleName'. Select the installer module 7zSD.sfx, 7zS2.sfx, or 7zS.sfx so RunProgram is honored."
    }
    if (-not (Test-CodeSigningCertificate -Certificate $Certificate)) { throw 'The selected signing certificate is not valid for code signing.' }

    $source = Get-CanonicalPath $PackagePath
    $destinationDirectory = Split-Path -Parent $OutputPath
    if (-not (Test-Path -LiteralPath $destinationDirectory -PathType Container)) {
        throw "Output folder not found: $destinationDirectory"
    }
    if (Test-PathWithin -Candidate $destinationDirectory -Parent $source) {
        throw 'The output folder cannot be inside the PSADT package folder.'
    }
    Assert-NoReparsePoints -RootPath $source
    Assert-DirectoryChainHasNoReparsePoint -Path $destinationDirectory

    $workRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('PSADT-SFX-' + [guid]::NewGuid().ToString('N'))
    $stagingPath = Join-Path $workRoot 'payload'
    $archivePath = Join-Path $workRoot 'payload.7z'
    $configPath = Join-Path $workRoot 'config.txt'
    $unsignedPath = Join-Path $workRoot 'unsigned.exe'
    $candidatePath = Join-Path $destinationDirectory ('.' + [System.IO.Path]::GetFileName($OutputPath) + '.' + [guid]::NewGuid().ToString('N') + '.tmp.exe')

    try {
        New-Item -ItemType Directory -Path $stagingPath -Force | Out-Null
        & $Log "Copying package into an isolated staging folder..."
        Get-ChildItem -LiteralPath $source -Force -ErrorAction Stop |
            Copy-Item -Destination $stagingPath -Recurse -Force -ErrorAction Stop

        # RunProgram resolves powershell.exe through the Windows executable
        # search path because stock installer SFX modules do not consistently
        # expand %SystemRoot%. Prevent a package-local executable from
        # shadowing the trusted Windows PowerShell binary.
        $shadowPowerShell = Join-Path $stagingPath 'powershell.exe'
        if (Test-Path -LiteralPath $shadowPowerShell -PathType Leaf) {
            throw 'The package root contains powershell.exe, which would shadow Windows PowerShell during SFX launch.'
        }

        $launcherPath = Join-Path $stagingPath 'SfxLauncher.ps1'
        Write-Utf8WithoutBom -Path $launcherPath -Content (New-SfxLauncherContent -EntryScriptName $EntryScriptName)
        & $Log 'Signing the embedded PowerShell launcher...'
        $launcherSignature = Set-AuthenticodeSignature -FilePath $launcherPath -Certificate $Certificate -TimestampServer $TimestampServer -HashAlgorithm SHA256
        if ($launcherSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            throw "Embedded launcher signing did not produce a valid signature: $($launcherSignature.Status) - $($launcherSignature.StatusMessage)"
        }

        & $Log 'Compressing package with 7-Zip...'
        [void](Invoke-SevenZipArchive -SevenZipPath $SevenZipPath -StagingPath $stagingPath -ArchivePath $archivePath)

        $title = ("Install {0} {1} {2}" -f $Vendor, $AppName, $Version).Trim()
        $safeTitle = $title.Replace('"', "'").Replace("`r", ' ').Replace("`n", ' ')
        $config = @"
;!@Install@!UTF-8!
Title="$safeTitle"
Progress="no"
Directory=""
RunProgram="powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"%%T\\SfxLauncher.ps1\""
;!@InstallEnd@!
"@
        Write-Utf8WithoutBom -Path $configPath -Content $config

        & $Log 'Assembling self-extracting executable...'
        Join-BinaryFiles -InputPaths @($SfxModulePath, $configPath, $archivePath) -OutputPath $unsignedPath
        Test-SevenZipPayload -SevenZipPath $SevenZipPath -ArchivePath $unsignedPath
        Copy-Item -LiteralPath $unsignedPath -Destination $candidatePath -Force

        $moduleHash = (Get-FileHash -LiteralPath $SfxModulePath -Algorithm SHA256).Hash
        & $Log ("SFX module SHA-256: {0}" -f $moduleHash)
        & $Log ("Signing with certificate {0}..." -f $Certificate.Thumbprint)
        $signature = Set-AuthenticodeSignature -FilePath $candidatePath -Certificate $Certificate -TimestampServer $TimestampServer -HashAlgorithm SHA256
        if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            throw "Authenticode signing did not produce a valid signature: $($signature.Status) - $($signature.StatusMessage)"
        }

        $verification = Get-AuthenticodeSignature -FilePath $candidatePath
        if ($verification.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            throw "Signature verification failed: $($verification.Status) - $($verification.StatusMessage)"
        }
        & $Log 'Verifying the signed executable payload...'
        Test-SevenZipPayload -SevenZipPath $SevenZipPath -ArchivePath $candidatePath
        Publish-VerifiedFile -CandidatePath $candidatePath -DestinationPath $OutputPath

        return [pscustomobject]@{
            OutputPath = $OutputPath
            Size       = (Get-Item -LiteralPath $OutputPath).Length
            Signature  = $verification.Status
        }
    } catch {
        if (Test-Path -LiteralPath $candidatePath -PathType Leaf) {
            Remove-Item -LiteralPath $candidatePath -Force -ErrorAction SilentlyContinue
        }
        throw
    } finally {
        if (Test-Path -LiteralPath $workRoot) {
            Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="PSADT SFX Builder" Height="720" Width="920" MinHeight="680" MinWidth="860"
        WindowStartupLocation="CenterScreen" Background="#111827" Foreground="#F9FAFB"
        FontFamily="Segoe UI" FontSize="14">
    <Window.Resources>
        <Style TargetType="TextBlock"><Setter Property="Foreground" Value="#E5E7EB"/></Style>
        <Style TargetType="TextBox">
            <Setter Property="Background" Value="#1F2937"/><Setter Property="Foreground" Value="#F9FAFB"/>
            <Setter Property="BorderBrush" Value="#374151"/><Setter Property="Padding" Value="9,7"/>
        </Style>
        <Style TargetType="ComboBox">
            <Setter Property="Background" Value="#1F2937"/><Setter Property="Foreground" Value="#111827"/>
            <Setter Property="BorderBrush" Value="#374151"/><Setter Property="Padding" Value="7,5"/>
        </Style>
        <Style TargetType="Button">
            <Setter Property="Background" Value="#2563EB"/><Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderThickness" Value="0"/><Setter Property="Padding" Value="14,8"/>
            <Setter Property="Cursor" Value="Hand"/><Setter Property="FontWeight" Value="SemiBold"/>
        </Style>
        <Style x:Key="SecondaryButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
            <Setter Property="Background" Value="#374151"/>
        </Style>
    </Window.Resources>
    <Grid Margin="28">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/><RowDefinition Height="20"/><RowDefinition Height="Auto"/>
            <RowDefinition Height="16"/><RowDefinition Height="Auto"/><RowDefinition Height="16"/>
            <RowDefinition Height="Auto"/><RowDefinition Height="16"/><RowDefinition Height="Auto"/>
            <RowDefinition Height="16"/><RowDefinition Height="*"/><RowDefinition Height="16"/><RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <StackPanel Grid.Row="0">
            <TextBlock Text="PSADT SFX Builder" FontSize="30" FontWeight="Bold" Foreground="White"/>
            <TextBlock Text="Build a signed off-network installer that launches PSADT in native 64-bit PowerShell." Margin="0,5,0,0" Foreground="#9CA3AF"/>
        </StackPanel>

        <Border Grid.Row="2" Background="#182233" CornerRadius="10" Padding="18">
            <Grid>
                <Grid.ColumnDefinitions><ColumnDefinition Width="170"/><ColumnDefinition Width="*"/><ColumnDefinition Width="100"/></Grid.ColumnDefinitions>
                <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="12"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
                <TextBlock Text="PSADT package" VerticalAlignment="Center"/>
                <TextBox x:Name="PackagePathBox" Grid.Column="1"/>
                <Button x:Name="BrowsePackageButton" Grid.Column="2" Content="Browse" Margin="10,0,0,0" Style="{StaticResource SecondaryButton}"/>
                <TextBlock Grid.Row="2" Text="Output folder" VerticalAlignment="Center"/>
                <TextBox x:Name="OutputPathBox" Grid.Row="2" Grid.Column="1"/>
                <Button x:Name="BrowseOutputButton" Grid.Row="2" Grid.Column="2" Content="Browse" Margin="10,0,0,0" Style="{StaticResource SecondaryButton}"/>
            </Grid>
        </Border>

        <Border Grid.Row="4" Background="#182233" CornerRadius="10" Padding="18">
            <Grid>
                <Grid.ColumnDefinitions><ColumnDefinition Width="110"/><ColumnDefinition Width="*"/><ColumnDefinition Width="24"/><ColumnDefinition Width="110"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="12"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
                <TextBlock Text="Vendor" VerticalAlignment="Center"/><TextBox x:Name="VendorBox" Grid.Column="1"/>
                <TextBlock Text="Application" Grid.Column="3" VerticalAlignment="Center"/><TextBox x:Name="AppNameBox" Grid.Column="4"/>
                <TextBlock Grid.Row="2" Text="Version" VerticalAlignment="Center"/><TextBox x:Name="VersionBox" Grid.Row="2" Grid.Column="1"/>
                <TextBlock x:Name="DetectedScriptText" Grid.Row="2" Grid.Column="3" Grid.ColumnSpan="2" Foreground="#93C5FD" VerticalAlignment="Center"/>
            </Grid>
        </Border>

        <Border Grid.Row="6" Background="#182233" CornerRadius="10" Padding="18">
            <Grid>
                <Grid.ColumnDefinitions><ColumnDefinition Width="170"/><ColumnDefinition Width="*"/><ColumnDefinition Width="100"/></Grid.ColumnDefinitions>
                <TextBlock Text="Signing certificate" VerticalAlignment="Center"/>
                <ComboBox x:Name="CertificateBox" Grid.Column="1" DisplayMemberPath="Display"/>
                <Button x:Name="RefreshCertificatesButton" Grid.Column="2" Content="Refresh" Margin="10,0,0,0" Style="{StaticResource SecondaryButton}"/>
            </Grid>
        </Border>

        <StackPanel Grid.Row="8">
            <TextBlock x:Name="OutputNameText" Text="Output: FTP-VendorAppName-Version.exe" FontSize="16" FontWeight="SemiBold" Foreground="#93C5FD"/>
            <ProgressBar x:Name="BuildProgress" Height="8" Margin="0,10,0,0" Minimum="0" Maximum="100" Value="0"
                         Background="#243244" Foreground="#2563EB" BorderThickness="0"/>
        </StackPanel>

        <Grid Grid.Row="10">
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="8"/><RowDefinition Height="*"/></Grid.RowDefinitions>
            <TextBlock Text="Build log" FontWeight="SemiBold" Foreground="#D1D5DB"/>
            <TextBox x:Name="LogBox" Grid.Row="2" IsReadOnly="True" AcceptsReturn="True" VerticalScrollBarVisibility="Auto"
                     TextWrapping="Wrap" Background="#0B1220" BorderBrush="#243244" FontFamily="Consolas" FontSize="12"/>
        </Grid>

        <Grid Grid.Row="12">
            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
            <TextBlock x:Name="StatusText" Text="Ready" VerticalAlignment="Center" Foreground="#9CA3AF"/>
            <Button x:Name="BuildButton" Grid.Column="1" Content="Build and Sign Installer" Padding="22,11"/>
        </Grid>
    </Grid>
</Window>
'@

$reader = New-Object System.Xml.XmlNodeReader($xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

$PackagePathBox = $window.FindName('PackagePathBox')
$OutputPathBox = $window.FindName('OutputPathBox')
$VendorBox = $window.FindName('VendorBox')
$AppNameBox = $window.FindName('AppNameBox')
$VersionBox = $window.FindName('VersionBox')
$DetectedScriptText = $window.FindName('DetectedScriptText')
$CertificateBox = $window.FindName('CertificateBox')
$OutputNameText = $window.FindName('OutputNameText')
$BuildProgress = $window.FindName('BuildProgress')
$LogBox = $window.FindName('LogBox')
$StatusText = $window.FindName('StatusText')
$BuildButton = $window.FindName('BuildButton')

function Add-UiLog {
    param([string]$Message)
    $line = '[{0:HH:mm:ss}] {1}' -f (Get-Date), $Message
    $LogBox.AppendText($line + [Environment]::NewLine)
    $LogBox.ScrollToEnd()
    $window.Dispatcher.Invoke([action]{}, [Windows.Threading.DispatcherPriority]::Background)
}

function Set-Busy {
    param([bool]$Busy, [string]$Message = 'Ready')
    $BuildButton.IsEnabled = -not $Busy
    $StatusText.Text = $Message
    $BuildProgress.IsIndeterminate = $Busy
    if (-not $Busy) {
        $BuildProgress.Value = if ($Message -match '(?i)completed successfully') { 100 } else { 0 }
    }
    $window.Cursor = if ($Busy) { [System.Windows.Input.Cursors]::Wait } else { [System.Windows.Input.Cursors]::Arrow }
    $window.Dispatcher.Invoke([action]{}, [Windows.Threading.DispatcherPriority]::Background)
}

function Update-OutputName {
    $vendor = ConvertTo-SafeFilePart $VendorBox.Text
    $app = ConvertTo-SafeFilePart $AppNameBox.Text
    $version = ConvertTo-SafeFilePart $VersionBox.Text
    $name = 'FTP-{0}{1}-{2}.exe' -f $vendor, $app, $version
    $OutputNameText.Text = "Output: $name"
    return $name
}

function Refresh-CertificateList {
    $certificates = @(Get-CodeSigningCertificates)
    $CertificateBox.ItemsSource = $certificates
    if ($certificates.Count -gt 0) {
        $CertificateBox.SelectedIndex = 0
        Add-UiLog "Found $($certificates.Count) usable code-signing certificate(s)."
    } else {
        Add-UiLog 'No valid code-signing certificates with private keys were found.'
    }
}

function Load-PackageInfo {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $info = Get-PsadtPackageInfo -PackagePath $Path
    $script:DetectedEntryScript = $info.EntryScriptName
    $VendorBox.Text = $info.Vendor
    $AppNameBox.Text = $info.AppName
    $VersionBox.Text = $info.Version
    $DetectedScriptText.Text = "Entry script: $($info.EntryScriptName)"
    if ([string]::IsNullOrWhiteSpace($OutputPathBox.Text)) {
        $OutputPathBox.Text = Split-Path -Parent (Get-CanonicalPath $Path)
    }
    [void](Update-OutputName)
    Add-UiLog "Loaded package: $Path"
    Add-UiLog "Detected entry script: $($info.EntryScriptName)"
}

$script:SevenZipPath = [string](Find-SevenZipExecutable)

$browseFolder = {
    param($targetBox, [string]$Description)
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = $Description
    $dialog.ShowNewFolderButton = $true
    if (-not [string]::IsNullOrWhiteSpace($targetBox.Text) -and (Test-Path -LiteralPath $targetBox.Text -PathType Container)) {
        $dialog.SelectedPath = $targetBox.Text
    }
    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $targetBox.Text = $dialog.SelectedPath
        return $true
    }
    return $false
}

$window.FindName('BrowsePackageButton').Add_Click({
    try {
        if (& $browseFolder $PackagePathBox 'Select the PSADT package folder') {
            Load-PackageInfo -Path $PackagePathBox.Text
        }
    } catch {
        Add-UiLog "ERROR: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($window, $_.Exception.Message, $script:ToolName, 'OK', 'Error') | Out-Null
    }
})

$window.FindName('BrowseOutputButton').Add_Click({
    [void](& $browseFolder $OutputPathBox 'Select the output folder')
})

$window.FindName('RefreshCertificatesButton').Add_Click({ Refresh-CertificateList })

foreach ($box in @($VendorBox, $AppNameBox, $VersionBox)) {
    $box.Add_TextChanged({ [void](Update-OutputName) })
}

$PackagePathBox.Add_LostFocus({
    if (-not [string]::IsNullOrWhiteSpace($PackagePathBox.Text) -and (Test-Path -LiteralPath $PackagePathBox.Text -PathType Container)) {
        try { Load-PackageInfo -Path $PackagePathBox.Text } catch { Add-UiLog "Package detection failed: $($_.Exception.Message)" }
    }
})

$BuildButton.Add_Click({
    Set-Busy -Busy $true -Message 'Building installer...'
    try {
        $packagePath = $PackagePathBox.Text.Trim()
        $outputDirectory = $OutputPathBox.Text.Trim()
        $vendor = $VendorBox.Text.Trim()
        $appName = $AppNameBox.Text.Trim()
        $version = $VersionBox.Text.Trim()
        $sevenZip = $script:SevenZipPath
        $sfxModule = $script:SfxModulePath
        $timestampServer = $script:TimestampServer

        if ([string]::IsNullOrWhiteSpace($packagePath)) { throw 'Select a PSADT package folder.' }
        $packageInfo = Get-PsadtPackageInfo -PackagePath $packagePath
        $script:DetectedEntryScript = $packageInfo.EntryScriptName
        if ([string]::IsNullOrWhiteSpace($vendor)) { throw 'Enter the application vendor.' }
        if ([string]::IsNullOrWhiteSpace($appName)) { throw 'Enter the application name.' }
        if ([string]::IsNullOrWhiteSpace($version)) { throw 'Enter the application version.' }
        if ([string]::IsNullOrWhiteSpace($outputDirectory)) { throw 'Select an output folder.' }
        if ([string]::IsNullOrWhiteSpace($sevenZip)) { throw '7-Zip was not detected. Install 7-Zip, then restart the builder.' }
        if ([string]::IsNullOrWhiteSpace($sfxModule)) { throw 'Set $script:SfxModulePath near the top of this script.' }
        if ([string]::IsNullOrWhiteSpace($timestampServer)) { throw 'Set $script:TimestampServer near the top of this script.' }
        if (-not $CertificateBox.SelectedItem) { throw 'Select a code-signing certificate.' }

        $outputName = Update-OutputName
        $outputPath = Join-Path $outputDirectory $outputName
        if (Test-Path -LiteralPath $outputPath -PathType Leaf) {
            $choice = [System.Windows.MessageBox]::Show(
                $window,
                "The output already exists:`r`n$outputPath`r`n`r`nReplace it?",
                $script:ToolName,
                'YesNo',
                'Warning'
            )
            if ($choice -ne [System.Windows.MessageBoxResult]::Yes) {
                Add-UiLog 'Build cancelled; existing output was left unchanged.'
                Set-Busy -Busy $false -Message 'Build cancelled'
                return
            }
        }

        $certificate = $CertificateBox.SelectedItem.Certificate
        Add-UiLog "Building $outputName"
        $result = New-PsadtSfx `
            -PackagePath $packagePath `
            -Vendor $vendor `
            -AppName $appName `
            -Version $version `
            -EntryScriptName $packageInfo.EntryScriptName `
            -OutputPath $outputPath `
            -SevenZipPath $sevenZip `
            -SfxModulePath $sfxModule `
            -Certificate $certificate `
            -TimestampServer $timestampServer `
            -Log { param($message) Add-UiLog $message }

        Add-UiLog ('SUCCESS: {0} ({1:N1} MB), signature: {2}' -f $result.OutputPath, ($result.Size / 1MB), $result.Signature)
        Set-Busy -Busy $false -Message 'Build completed successfully'
        [System.Windows.MessageBox]::Show(
            $window,
            "Signed installer created successfully:`r`n`r`n$($result.OutputPath)",
            $script:ToolName,
            'OK',
            'Information'
        ) | Out-Null
    } catch {
        Add-UiLog "ERROR: $($_.Exception.Message)"
        Set-Busy -Busy $false -Message 'Build failed'
        [System.Windows.MessageBox]::Show($window, $_.Exception.Message, $script:ToolName, 'OK', 'Error') | Out-Null
    } finally {
        if (-not $BuildButton.IsEnabled) { Set-Busy -Busy $false -Message $StatusText.Text }
    }
})

Refresh-CertificateList
if (-not $script:SevenZipPath) {
    Add-UiLog 'WARNING: 7-Zip was not detected. Install 7-Zip, then restart the builder.'
    [System.Windows.MessageBox]::Show(
        $window,
        '7-Zip was not detected. Install 7-Zip, then restart the builder.',
        $script:ToolName,
        'OK',
        'Warning'
    ) | Out-Null
} else {
    Add-UiLog "Detected 7-Zip: $($script:SevenZipPath)"
}
Add-UiLog "$($script:ToolName) v$($script:ToolVersion) ready."
[void]$window.ShowDialog()
