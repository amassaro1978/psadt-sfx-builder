# PSADT SFX Builder

A focused Windows PowerShell 5.1/WPF utility that turns a PSAppDeployToolkit package into a signed, self-extracting installer for off-network users.

The generated filename is:

```text
FTP-VendorAppName-Version.exe
```

## What it does

1. Selects a trusted PSADT package folder.
2. Detects the root PSADT entry script and reads `AppVendor`, `AppName`, and `AppVersion` where available.
3. Copies the package to an isolated temporary staging folder.
4. Adds and Authenticode-signs a small PowerShell launcher that:
   - is started through Windows' executable search path after the builder rejects any package-local `powershell.exe` that could shadow the system copy;
   - relaunches through `%WINDIR%\Sysnative\WindowsPowerShell\v1.0\powershell.exe` when a 32-bit SFX starts on 64-bit Windows;
   - requests elevation;
   - runs the PSADT entry script with `-DeploymentType Install -DeployMode Interactive`;
   - waits for PSADT to finish.

No custom `SfxLauncher.exe` is generated or embedded. This avoids introducing an unsigned, dynamically compiled executable that endpoint security products reasonably treat as suspicious.
5. Compresses the staged package with 7-Zip.
6. Combines an installer SFX module, its configuration, and the archive.
7. Tests the unsigned SFX payload.
8. Signs the final EXE with the selected code-signing certificate and SHA-256 timestamp.
9. Verifies both the Authenticode signature and the signed SFX payload.
10. Publishes the verified file only after every check passes, preserving an existing good installer if the new build fails.

The interface includes an indeterminate build progress meter and a live log showing package detection, staging, compression, assembly, signing, and verification.

The native relaunch is intentional: native PowerShell registry commands execute in the 64-bit registry view on 64-bit Windows unless the package explicitly chooses another view.

## Requirements

- Windows 10/11 or Windows Server with Windows PowerShell 5.1.
- 7-Zip `7z.exe`.
  - It is detected automatically under the native or x86 Program Files locations. The GUI displays a warning if it is missing.
- A **7-Zip installer SFX module**, preferably `7zSD.sfx` or `7zS2.sfx` (`7zS.sfx` from older packages is also accepted).
  - These are supplied separately in the 7-Zip Extra/LZMA SDK package, depending on 7-Zip version.
  - Do not use ordinary `7z.sfx`; it is an extraction module and is rejected because it does not provide the required installer `RunProgram` behavior.
- A valid code-signing certificate with an accessible private key in:
  - `Cert:\CurrentUser\My`, or
  - `Cert:\LocalMachine\My`.
- Network access to the configured timestamp server while building.

No certificate or private-key material is copied into the generated installer or saved in this repository.

Set these build-station values near the top of `PSADT-SFX-Builder.ps1` before first use:

```powershell
$script:SfxModulePath = 'C:\Program Files\7-Zip\7zSD.sfx'
$script:TimestampServer = 'http://timestamp.digicert.com'
```

### Stock 7-Zip exit-code limitation

The package-local launchers wait for PSADT and preserve its exit code between themselves. However, stock 7-Zip installer SFX modules are known to return `0` instead of reliably forwarding the launched program's exit code. Do not use the outer `FTP-*.exe` process code as deployment success telemetry unless your organization supplies a pinned, independently tested SFX module that documents child exit-code propagation. Use PSADT logs for the initial release.

## Run

Double-click `Start-PSADT-SFX-Builder.cmd`, which selects native Windows PowerShell and opens the GUI without a console window.

Or run it directly from 64-bit Windows PowerShell 5.1:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\PSADT-SFX-Builder.ps1
```

Then:

1. Select the PSADT package folder.
2. Confirm the Vendor, Application, and Version automatically read from the PSADT script; edit only if needed.
3. Select the output folder.
4. Select the signing certificate.
5. Choose **Build and Sign Installer**.

## Package expectations

The selected folder must contain a PSADT entry script in its root. Detection order is:

1. `Invoke-AppDeployToolkit.ps1`;
2. a root PowerShell script containing `Open-ADTSession` and `Install-ADTDeployment`;
3. the only root `.ps1` file, when exactly one exists.

The builder rejects package and output paths containing reparse points, requires an existing output folder, and refuses to write output inside the source package folder.

## Windows validation checklist

Test the first generated installer on a disposable Windows endpoint before production use:

1. Right-click the generated EXE, open **Properties → Digital Signatures**, and verify the expected signer and timestamp.
2. Launch it as a standard user and verify one UAC prompt appears.
3. Confirm the normal interactive PSADT UI appears without a PowerShell console.
4. Confirm the PSADT log records the expected success/reboot result. Do not assume a stock 7-Zip SFX forwards that code to its own caller.
5. For a test package that writes `HKLM:\Software\YourTestKey` with native PowerShell commands, confirm the value appears in the 64-bit registry view and not only under `WOW6432Node`.
6. Test a package path and output path containing spaces.
7. Test an MSI package and an EXE package.
8. Confirm a failed replacement preserves the prior signed installer and removes only the temporary candidate.

## Security notes

- Only package folders you trust. The generated EXE intentionally elevates and runs the selected PSADT script.
- The source package is staged locally before compression; the source is never modified.
- A candidate EXE is signed and verified under a unique temporary name; the final path is replaced only after success.
- Temporary build files are removed in a `finally` block.
