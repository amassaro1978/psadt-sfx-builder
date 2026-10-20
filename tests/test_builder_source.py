import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "PSADT-SFX-Builder.ps1").read_text(encoding="utf-8-sig")
LAUNCHER = (ROOT / "Start-PSADT-SFX-Builder.cmd").read_text(encoding="utf-8")


def function_body(name: str) -> str:
    marker = f"function {name}"
    start = SOURCE.index(marker)
    next_function = SOURCE.find("\nfunction ", start + len(marker))
    return SOURCE[start:] if next_function == -1 else SOURCE[start:next_function]


class BuilderSourceTests(unittest.TestCase):
    def test_gui_scope_disables_strict_mode_for_windows_powershell_wpf(self):
        launcher_start = SOURCE.index("function New-SfxLauncherContent")
        self.assertIn("Set-StrictMode -Off", SOURCE[:launcher_start])
        launcher_body = function_body("New-SfxLauncherContent")
        self.assertIn("Set-StrictMode -Version 2.0", launcher_body)

    def test_builder_cmd_prefers_native_powershell(self):
        self.assertIn("%SystemRoot%\\System32\\WindowsPowerShell", LAUNCHER)
        self.assertIn("%SystemRoot%\\Sysnative\\WindowsPowerShell", LAUNCHER)
        self.assertIn('-File "%~dp0PSADT-SFX-Builder.ps1"', LAUNCHER)

    def test_wpf_xaml_is_well_formed_and_controls_are_unique(self):
        start_marker = "[xml]$xaml = @'\n"
        start = SOURCE.index(start_marker) + len(start_marker)
        end = SOURCE.index("\n'@\n", start)
        root = ET.fromstring(SOURCE[start:end])
        names = []
        for element in root.iter():
            for key, value in element.attrib.items():
                if key.endswith("}Name") or key == "Name":
                    names.append(value)
        self.assertEqual(len(names), len(set(names)))
        self.assertIn("BuildButton", names)
        self.assertIn("CertificateBox", names)
        self.assertIn("BuildProgress", names)
        self.assertIn("LogBox", names)
        self.assertNotIn("SevenZipBox", names)
        self.assertNotIn("SfxModuleBox", names)
        self.assertNotIn("TimestampBox", names)

    def test_output_name_contract(self):
        body = function_body("Update-OutputName")
        self.assertIn("'FTP-{0}{1}-{2}.exe'", body)
        self.assertIn("ConvertTo-SafeFilePart $VendorBox.Text", body)
        self.assertIn("ConvertTo-SafeFilePart $AppNameBox.Text", body)
        self.assertIn("ConvertTo-SafeFilePart $VersionBox.Text", body)

    def test_advanced_paths_are_configured_and_seven_zip_is_auto_detected(self):
        self.assertIn("$script:SfxModulePath =", SOURCE)
        self.assertIn("$script:TimestampServer =", SOURCE)
        body = function_body("Find-SevenZipExecutable")
        self.assertIn("'7z.exe'", body)
        self.assertNotIn(".sfx", body.lower())
        build_body = function_body("New-PsadtSfx")
        self.assertIn("Select the installer module 7zSD.sfx, 7zS2.sfx, or 7zS.sfx", build_body)

    def test_psadt_metadata_supports_v3_v4_and_header_comments(self):
        body = function_body("Get-PsadtMetadataValue")
        self.assertIn("\\$?", body)
        self.assertIn("$HeaderLabels", body)
        package = function_body("Get-PsadtPackageInfo")
        self.assertIn("-AssignmentName 'AppVendor'", package)
        self.assertIn("-AssignmentName 'AppName'", package)
        self.assertIn("-AssignmentName 'AppVersion'", package)

    def test_certificate_list_requires_code_signing_eku(self):
        body = function_body("Test-CodeSigningCertificate")
        self.assertIn("1.3.6.1.5.5.7.3.3", body)
        self.assertIn("if (-not $ekuExtension) { return $false }", body)

    def test_progress_and_logging_are_wired(self):
        busy = function_body("Set-Busy")
        self.assertIn("$BuildProgress.IsIndeterminate = $Busy", busy)
        log = function_body("Add-UiLog")
        self.assertIn("$LogBox.AppendText", log)

    def test_embedded_launcher_relaunches_native_before_elevation(self):
        start = SOURCE.index("function New-SfxLauncherContent")
        end = SOURCE.index("\nfunction Write-Utf8WithoutBom", start)
        body = SOURCE[start:end]
        native = body.index("[Environment]::Is64BitOperatingSystem")
        sysnative = body.index("Sysnative\\WindowsPowerShell")
        elevation = body.index("-Verb RunAs")
        invoke_psadt = body.index("-DeploymentType Install -DeployMode Interactive")
        self.assertLess(native, sysnative)
        self.assertLess(sysnative, elevation)
        self.assertLess(elevation, invoke_psadt)
        self.assertIn("-WindowStyle Hidden", body)
        self.assertIn("Get-Variable -Name LASTEXITCODE", body)

    def test_sfx_config_waits_for_hidden_launcher(self):
        body = function_body("New-PsadtSfx")
        self.assertIn(";!@Install@!UTF-8!", body)
        self.assertIn('Progress="no"', body)
        self.assertIn('Directory=""', body)
        self.assertIn('RunProgram="powershell.exe ', body)
        self.assertIn('-WindowStyle Hidden -File \\"%%T\\\\SfxLauncher.ps1\\"', body)
        self.assertNotIn("nowait:", body.lower())
        self.assertNotIn("SfxLauncher.exe", SOURCE)
        self.assertNotIn("Add-Type -TypeDefinition", SOURCE)

    def test_package_cannot_shadow_windows_powershell(self):
        body = function_body("New-PsadtSfx")
        rejection = body.index("$shadowPowerShell = Join-Path $stagingPath 'powershell.exe'")
        config = body.index('RunProgram="powershell.exe ')
        self.assertLess(rejection, config)
        self.assertIn("would shadow Windows PowerShell", body)

    def test_embedded_launcher_is_signed_before_archiving(self):
        body = function_body("New-PsadtSfx")
        sign = body.index("Set-AuthenticodeSignature -FilePath $launcherPath")
        archive = body.index("Invoke-SevenZipArchive")
        self.assertLess(sign, archive)

    def test_payload_and_signature_are_both_verified(self):
        body = function_body("New-PsadtSfx")
        assemble = body.index("Join-BinaryFiles")
        unsigned_test = body.index("Test-SevenZipPayload", assemble)
        sign = body.index("Set-AuthenticodeSignature -FilePath $candidatePath")
        signature_verify = body.index("Get-AuthenticodeSignature", sign)
        signed_test = body.index("Test-SevenZipPayload", signature_verify)
        self.assertLess(assemble, unsigned_test)
        self.assertLess(unsigned_test, sign)
        self.assertLess(sign, signature_verify)
        self.assertLess(signature_verify, signed_test)
        self.assertIn("-HashAlgorithm SHA256", body)
        self.assertIn("Set-AuthenticodeSignature -FilePath $candidatePath", body)
        self.assertIn("Publish-VerifiedFile -CandidatePath $candidatePath", body)

    def test_failure_removes_only_candidate_and_temp_files(self):
        body = function_body("New-PsadtSfx")
        self.assertRegex(
            body,
            re.compile(r"catch\s*\{.*Remove-Item -LiteralPath \$candidatePath", re.DOTALL),
        )
        catch_body = body[body.index("    } catch {") :]
        self.assertNotIn("Remove-Item -LiteralPath $OutputPath", catch_body)
        self.assertRegex(
            body,
            re.compile(r"finally\s*\{.*Remove-Item -LiteralPath \$workRoot", re.DOTALL),
        )

        publish = function_body("Publish-VerifiedFile")
        self.assertIn("$backupPath", publish)
        self.assertIn("Move-Item -LiteralPath $backupPath -Destination $DestinationPath", publish)

    def test_source_package_reparse_points_are_rejected(self):
        body = function_body("Assert-NoReparsePoints")
        self.assertIn("[System.IO.FileAttributes]::ReparsePoint", body)
        self.assertIn("System.Collections.Generic.Stack", body)
        self.assertNotIn("-Recurse", body)

        build = function_body("New-PsadtSfx")
        self.assertIn("Assert-NoReparsePoints -RootPath $source", build)
        self.assertIn("Assert-DirectoryChainHasNoReparsePoint -Path $destinationDirectory", build)


if __name__ == "__main__":
    unittest.main()
