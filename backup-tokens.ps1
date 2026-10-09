$ErrorActionPreference = 'Stop'

$installerRoot = $PSScriptRoot
$sharedDir = Join-Path $installerRoot 'Shared'
$backupPath = Join-Path $sharedDir 'token-backup.json'
$sourceTokenPath = Join-Path $sharedDir 'source-repo-token.txt'
$sharedConfigTokenPath = Join-Path $sharedDir 'shared-config-token.txt'

function ConvertFrom-LocalProtectedToken {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return ''
    }

    $encrypted = (Get-Content -Raw -LiteralPath $Path).Trim()
    if ([string]::IsNullOrWhiteSpace($encrypted)) {
        return ''
    }

    $secure = ConvertTo-SecureString $encrypted
    $credential = New-Object System.Management.Automation.PSCredential('token', $secure)
    return $credential.GetNetworkCredential().Password
}

function ConvertFrom-SharedProtectedValue {
    param([string]$Value)

    $prefix = 'shared:v1:'
    if ([string]::IsNullOrWhiteSpace($Value) -or -not $Value.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $Value
    }

    $purpose = 'Mercury Survey Programming shared repository token configuration'
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $key = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($purpose))
    $allBytes = [System.Convert]::FromBase64String($Value.Substring($prefix.Length))
    $iv = New-Object byte[] 16
    [System.Array]::Copy($allBytes, 0, $iv, 0, 16)
    $cipher = New-Object byte[] ($allBytes.Length - 16)
    [System.Array]::Copy($allBytes, 16, $cipher, 0, $cipher.Length)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.IV = $iv

    $decryptor = $aes.CreateDecryptor()
    $plainBytes = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length)
    return [System.Text.Encoding]::UTF8.GetString($plainBytes)
}

function Get-SharedConfigToken {
    if (-not (Test-Path -LiteralPath $sharedConfigTokenPath)) {
        return ''
    }

    $raw = (Get-Content -Raw -LiteralPath $sharedConfigTokenPath).Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return ''
    }

    $values = @{}
    foreach ($line in $raw -split "`r?`n") {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) {
            continue
        }

        $separator = $trimmed.IndexOf('=')
        if ($separator -gt 0) {
            $values[$trimmed.Substring(0, $separator).Trim()] = $trimmed.Substring($separator + 1).Trim()
        }
    }

    foreach ($key in @('githubTokenEncrypted', 'githubToken', 'token')) {
        if ($values.ContainsKey($key)) {
            return (ConvertFrom-SharedProtectedValue $values[$key]).Trim()
        }
    }

    return (ConvertFrom-SharedProtectedValue (($raw -split "`r?`n")[0].Trim())).Trim()
}

function ConvertFrom-SecureStringToPlainText {
    param([securestring]$SecureString)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Protect-TokenBackupPayload {
    param(
        [string]$Json,
        [string]$Password
    )

    $salt = New-Object byte[] 16
    $iv = New-Object byte[] 16
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($iv)

    $derive = New-Object Security.Cryptography.Rfc2898DeriveBytes(
        $Password,
        $salt,
        200000,
        [Security.Cryptography.HashAlgorithmName]::SHA256)
    $key = $derive.GetBytes(32)

    $aes = [Security.Cryptography.Aes]::Create()
    $aes.Mode = [Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.IV = $iv

    $plainBytes = [Text.Encoding]::UTF8.GetBytes($Json)
    $encryptor = $aes.CreateEncryptor()
    $cipherBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)

    return [pscustomobject]@{
        format = 'MercurySurveyProgrammingTokenBackup'
        version = 1
        kdf = 'PBKDF2-SHA256'
        iterations = 200000
        salt = [Convert]::ToBase64String($salt)
        iv = [Convert]::ToBase64String($iv)
        cipherText = [Convert]::ToBase64String($cipherBytes)
    }
}

if (-not (Test-Path -LiteralPath $sharedDir)) {
    New-Item -ItemType Directory -Force -Path $sharedDir | Out-Null
}

$password = Read-Host 'Enter backup password' -AsSecureString
$confirmPassword = Read-Host 'Confirm backup password' -AsSecureString
$plainPassword = ConvertFrom-SecureStringToPlainText $password
$plainConfirmPassword = ConvertFrom-SecureStringToPlainText $confirmPassword

if ([string]::IsNullOrWhiteSpace($plainPassword)) {
    throw 'Backup password cannot be blank.'
}

if (-not [string]::Equals($plainPassword, $plainConfirmPassword, [StringComparison]::Ordinal)) {
    throw 'Backup passwords do not match.'
}

$payload = [pscustomobject]@{
    createdAt = (Get-Date).ToString('o')
    computerName = $env:COMPUTERNAME
    userName = $env:USERNAME
    tokens = [pscustomobject]@{
        sharedConfigurationGithubToken = Get-SharedConfigToken
        sourceRepositoryGithubToken = ConvertFrom-LocalProtectedToken $sourceTokenPath
    }
}

$payloadJson = $payload | ConvertTo-Json -Depth 5 -Compress
$backup = Protect-TokenBackupPayload -Json $payloadJson -Password $plainPassword
$backup | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backupPath -Encoding UTF8

Write-Host "Token backup written to: $backupPath"
