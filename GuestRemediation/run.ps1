using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

$ErrorActionPreference = 'Stop'

New-Variable -Scope Script -Name 'tokenInfo' -Force

function RefreshJwtToken {
    $Token = Get-GraphTokenCert @authParams
    Connect-MgGraph -AccessToken $(ConvertTo-SecureString -String $Token.access_token -AsPlainText -Force)
    $script:tokenInfo = $token
    $script:tokenExpires = ([DateTimeOffset]([DateTime]::UtcNow)).AddSeconds(3500).ToUnixTimeSeconds()
    $script:managedJwt = $token.access_token
}

function IsTokenExpired {
    if (-not $tokenInfo) {
        throw "`$tokenInfo is null, Call RefreshJwtToken first."
    }
    # Check if it's good for more than the next ten seconds
    return $tokenExpires -lt (Epoch - 10)
}

function RefreshIfExpired {
    # Get the token if you don't have one
    if (-not $tokenInfo) {
        RefreshJwtToken
    }
    # Refresh it if it's too old
    if (IsTokenExpired) {
        RefreshJwtToken
    }
}

function DoWithRetry {
    param (
        [ScriptBlock]
        $Command,
        $RetryLimit=5,
        $Backoff=2,
        [ref]
        $ErrorVariable,
        [switch]
        $WriteToErrorStream,
        $ArgumentList
    )
    begin {
        function GetBackoffTime {
            # Binary exponential backoff 
            # if you've retried 100 times, do something else, this ain't happenin
            param ([ValidateRange(0,100)] $retries, $backoff=2)
            if ($retries -eq 0 -or $backoff -eq 0) { return 0 }
            [Math]::Pow($backoff, $retries)
        }
    }
    process {
        $retries   = 0
        $threshold = $RetryLimit
        $backoff   = $Backoff
        $tryAgain = $true

        $_Errors = @()

        :tryloop
        do {
            if ($threshold -le $retries) { break tryloop }
        
            $timeout = GetBackoffTime -retries $retries
            if ($timeout) { 
                Write-Debug "Waiting $timeout seconds after failure"
                Start-Sleep -Seconds $timeout
            }
        
            try {
                & $Command @ArgumentList
                                          
                $tryAgain = $false
            }
            catch {
                $_Errors += $_
                if ($WriteToErrorStream) {
                    Write-Error $_
                }
                $retries++
            }
        } while ($tryAgain)

        if ($ErrorVariable) {
            $ErrorVariable.Value = $_Errors
        }
    }
}

################################################################################
##                                    Main                                    ##
################################################################################

$graphUri = "https://graph.microsoft.com/v1.0"
Import-Module ./graphCertauth.psm1

Connect-AzAccount -Identity

$TenantInfo = Get-Content '.\tenant_config_json.json' | ConvertFrom-Json
$VaultName = 'kv-boxer'
$CertName =  $TenantInfo."$hometenant".CertName
$clientId  = $TenantInfo."$hometenant".ClientId
$tenantId  = $TenantInfo."$hometenant".TenantId

Write-Output "Getting Graph JWT"
try {
    $authParams = @{
        TenantName=$HomeTenant
        AppId=$clientId
        vaultName=$vaultName
        CertName=$CertName
        ResourceUri="https://graph.microsoft.com/.default"
    }

    RefreshJwtToken
    $Token = Get-GraphTokenCert @authParams
    Connect-MgGraph -AccessToken $(ConvertTo-SecureString -String $Token.access_token -AsPlainText -Force) 
}
catch {
    Write-Error "Issue getting JWT: " $_
    exit
}


# Write to the Azure Functions log stream.
Write-Host "PowerShell HTTP trigger function processed a request."

# Interact with query parameters or the body of the request.
$name = $Request.Query.Name
if (-not $name) {
    $name = $Request.Body.Name
}

$body = "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response."

if ($name) {
    $body = "Hello, $name. This HTTP triggered function executed successfully."
}

