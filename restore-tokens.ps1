$ErrorActionPreference = 'Stop'

$installerRoot = $PSScriptRoot
$sharedDir = Join-Path $installerRoot 'Shared'
$backupPath = Join-Path $sharedDir 'token-backup.json'
$sourceTokenPath = Join-Path $sharedDir 'source-repo-token.txt'
$sharedConfigTokenPath = Join-Path $sharedDir 'shared-config-token.txt'

function ConvertFrom-SecureStringToPlainText {
    param([securestring]$SecureString)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Unprotect-TokenBackupPayload {
    param(
        $Backup,
        [string]$Password
    )

    $salt = [Convert]::FromBase64String($Backup.salt)
    $iv = [Convert]::FromBase64String($Backup.iv)
    $cipherBytes = [Convert]::FromBase64String($Backup.cipherText)

    $derive = New-Object Security.Cryptography.Rfc2898DeriveBytes(
        $Password,
        $salt,
        [int]$Backup.iterations,
        [Security.Cryptography.HashAlgorithmName]::SHA256)
    $key = $derive.GetBytes(32)

    $aes = [Security.Cryptography.Aes]::Create()
    $aes.Mode = [Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.IV = $iv

    $decryptor = $aes.CreateDecryptor()
    $plainBytes = $decryptor.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length)
    return [Text.Encoding]::UTF8.GetString($plainBytes)
}

function Protect-SharedValue {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ''
    }

    $purpose = 'Mercury Survey Programming shared repository token configuration'
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $key = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($purpose))

    $iv = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($iv)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.IV = $iv

    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $encryptor = $aes.CreateEncryptor()
    $cipherBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
    $allBytes = New-Object byte[] ($iv.Length + $cipherBytes.Length)
    [System.Array]::Copy($iv, 0, $allBytes, 0, $iv.Length)
    [System.Array]::Copy($cipherBytes, 0, $allBytes, $iv.Length, $cipherBytes.Length)

    return 'shared:v1:' + [System.Convert]::ToBase64String($allBytes)
}

function Save-LocalProtectedToken {
    param(
        [string]$Path,
        [string]$Token
    )

    if ([string]::IsNullOrWhiteSpace($Token)) {
        return
    }

    $secure = ConvertTo-SecureString $Token -AsPlainText -Force
    $encrypted = ConvertFrom-SecureString $secure
    Set-Content -LiteralPath $Path -Value $encrypted -Encoding ASCII
}

if (-not (Test-Path -LiteralPath $backupPath)) {
    throw "Token backup file was not found: $backupPath"
}

if (-not (Test-Path -LiteralPath $sharedDir)) {
    New-Item -ItemType Directory -Force -Path $sharedDir | Out-Null
}

$password = Read-Host 'Enter backup password' -AsSecureString
$plainPassword = ConvertFrom-SecureStringToPlainText $password

$backup = Get-Content -Raw -LiteralPath $backupPath | ConvertFrom-Json
if ($backup.format -ne 'MercurySurveyProgrammingTokenBackup') {
    throw 'This is not a Mercury Survey Programming token backup file.'
}

$payloadJson = Unprotect-TokenBackupPayload -Backup $backup -Password $plainPassword
$payload = $payloadJson | ConvertFrom-Json

$sharedToken = [string]$payload.tokens.sharedConfigurationGithubToken
if (-not [string]::IsNullOrWhiteSpace($sharedToken)) {
    Set-Content -LiteralPath $sharedConfigTokenPath -Value ("githubTokenEncrypted=" + (Protect-SharedValue $sharedToken)) -Encoding ASCII
}

$sourceToken = [string]$payload.tokens.sourceRepositoryGithubToken
Save-LocalProtectedToken -Path $sourceTokenPath -Token $sourceToken

Write-Host "Tokens restored to: $sharedDir"
