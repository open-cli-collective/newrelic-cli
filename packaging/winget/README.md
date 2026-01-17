# Winget Manifests for newrelic-cli

This directory contains Winget manifest templates for newrelic-cli.

## Manifest Structure

Winget requires three separate manifest files:

```
winget/
├── OpenCliCollective.newrelic-cli.yaml              # Version manifest
├── OpenCliCollective.newrelic-cli.installer.yaml    # Installer manifest
├── OpenCliCollective.newrelic-cli.locale.en-US.yaml # Locale manifest
└── README.md                                        # This file
```

## How It Works

### Placeholder Values

The manifests contain placeholder values that are replaced at release time:

| Placeholder | Purpose | Example Replacement |
|-------------|---------|---------------------|
| `0.0.0` | Version | `1.0.14` |
| 64 zeros | SHA256 checksum | Actual hash from checksums.txt |

### Checksum Replacement

The installer manifest contains two 64-zero placeholders for checksums:
- First occurrence: x64 checksum
- Second occurrence: arm64 checksum

**Important**: PowerShell's `-replace` doesn't support a count parameter. Use .NET regex:

```powershell
$regex = [regex]"0{64}"
$content = $regex.Replace($content, $env:X64_HASH, 1)   # Replace first match
$content = $regex.Replace($content, $env:ARM64_HASH, 1) # Replace second match
```

## Package Identifier

The package identifier follows Winget naming conventions:
- Format: `Publisher.PackageName`
- Our identifier: `OpenCliCollective.newrelic-cli`

## Local Validation

To validate the manifests locally (requires Windows with winget installed):

```powershell
# Create a test directory with processed manifests
$testDir = "winget-test"
$testVersion = "0.0.1"
$testHash1 = "0000000000000000000000000000000000000000000000000000000000000001"
$testHash2 = "0000000000000000000000000000000000000000000000000000000000000002"

New-Item -ItemType Directory -Path $testDir -Force | Out-Null

# Process version manifest
$content = Get-Content "OpenCliCollective.newrelic-cli.yaml" -Raw
$content = $content -replace "0\.0\.0", $testVersion
Set-Content "$testDir/OpenCliCollective.newrelic-cli.yaml" $content

# Process locale manifest
$content = Get-Content "OpenCliCollective.newrelic-cli.locale.en-US.yaml" -Raw
$content = $content -replace "0\.0\.0", $testVersion
Set-Content "$testDir/OpenCliCollective.newrelic-cli.locale.en-US.yaml" $content

# Process installer manifest
$content = Get-Content "OpenCliCollective.newrelic-cli.installer.yaml" -Raw
$content = $content -replace "0\.0\.0", $testVersion
$regex = [regex]"0{64}"
$content = $regex.Replace($content, $testHash1, 1)
$content = $regex.Replace($content, $testHash2, 1)
Set-Content "$testDir/OpenCliCollective.newrelic-cli.installer.yaml" $content

# Validate
winget validate --manifest $testDir/
```

## Submission Process

Unlike Chocolatey (direct push), Winget submissions are **pull requests** to microsoft/winget-pkgs:

1. Release workflow processes templates with actual version and checksums
2. `wingetcreate submit` creates a PR to microsoft/winget-pkgs
3. Microsoft's automated validation runs
4. On success: Auto-merged within minutes
5. Users can install with: `winget install OpenCliCollective.newrelic-cli`

## References

- [Winget Manifest Schema](https://github.com/microsoft/winget-pkgs/tree/master/doc/manifest)
- [wingetcreate Tool](https://github.com/microsoft/winget-create)
- [Winget Package Repository](https://github.com/microsoft/winget-pkgs)
