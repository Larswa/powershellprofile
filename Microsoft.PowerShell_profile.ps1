# Default PowerShell Profile
$Error.Clear()


# Add-WindowsPSModulePath
# Import-Module windowscompatibility


function loadAzureCmd {
    #Loading Azure commandlets
    Import-Module Az -ErrorAction Inquire
    $psversion = get-module -ListAvailable -name Az -refresh |Select-object -Property Version
    if ($error.Count -eq 0) {Write-Host "Azure PS commandlets loadet. Version: $($psversion.Version)" -ForegroundColor Green}
    else {
        Write-Host "Azure (Az) PS commandlets loadet and ready...With some errors." -ForegroundColor Yellow
        Write-host $Error.Count
        Write-host $Error[0]
    }
}
Set-Alias -Name azure -Value loadAzureCmd -Description "Load Azure commandlets"



#Powershell Core credential manager
$CredentialManagerPath = "D:\Documents\PowerShell\CoreCredentialManager\CoreCredentialManager.psd1"
if (Test-Path -Path $CredentialManagerPath) {
    Import-Module $CredentialManagerPath
}



function loadVSCmd {
    #%comspec% /k
    #Set environment variables for Visual Studio Command Prompt
    if (Test-Path "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat") {
        Push-Location 'C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\'
        cmd /c "VsDevCmd.bat&set" |
            ForEach-Object {
            if ($_ -match "=") {
                $v = $_.split("="); set-item -force -path "ENV:\$($v[0])"  -value "$($v[1])"
            }
        }
        Pop-Location
        write-host "Visual Studio 2019 Command Prompt variables set." -ForegroundColor Green
    }
}
Set-Alias -Name vs -Value loadVSCmd -Description "Load Visual Studio command prompt variables"

Import-Module posh-git
$poshGitVersion = get-module -name posh-git |select-object -property Version
write-host "PoshGit loadet. Version: $($poshGitVersion.Version)" -ForegroundColor Green

if (test-path "d:\documents\PowerShell\Modules\oh-my-posh\") {
    Import-Module 'oh-my-posh'
}

# Chocolatey profile
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
}

#Set Git alias for cleaning dotnet projects
function gitcleanCmd {
    Invoke-Command -ScriptBlock {git clean -xdf -e '*.user *.lock.json ' }
}
Set-Alias -Name gitclean -Value gitcleanCmd -Description "Cleaning a dotnet project for all except .user files using Git Clean"


function lwa002Cmd {
    # Remote connect to lwa002 if creds are in the windows cred store
    if ($null -eq (Get-StoredCredential -Target "LWA002.LOCAL")) {
        Write-Host "Mangler creds for at remote PS til LWA002.LOCAL" -ForegroundColor Yellow
        New-StoredCredential -Target "LWA002.LOCAL" -Comment "Created from powershell profile" -Type Generic -Persist Enterprise -Credentials $(Get-credential -UserName "lwa002\lars" -Message "Prompt fra Profile") | out-null
    }
    if ($null -eq (get-childitem Cert:\LocalMachine\root | Where-Object {$_.Subject -eq "CN=lwa002.local"})) {
        Write-Host "Mangler Cert for at remote PS til LWA002.LOCAL Installeres nu" -ForegroundColor Yellow
        #Import-Certificate -FilePath "D:\SynologyDrive\Certifikater\LWA002.LOCAL.PublicKey.cer" -CertStoreLocation Cert:\LocalMachine\root
        Start-Process powershell.exe "Import-Certificate -FilePath `"D:\SynologyDrive\Certifikater\LWA002.LOCAL.PublicKey.cer`" -CertStoreLocation Cert:\LocalMachine\root" -NoNewWindow
    }
    if (($lwa002.State -eq "Broken") -or ($lwa002.State -eq "Closed")) {
        write-host "Der er noget galt med forbindelsen til lwa002 - fjerner og starter en ny session op"
        Remove-PSSession $lwa002
        Remove-Variable lwa002 -Scope "Global"
    }
    if (!$lwa002) {

        $global:lwa002 = New-PSSession -ComputerName LWA002.LOCAL -UseSSL -Credential $(Get-StoredCredential -Target LWA002.LOCAL -Type Generic) -Name lwa002
    }
    Enter-PSSession -Session $lwa002
}
Set-Alias -Name lwa002 -value lwa002Cmd


function topCmd {
    While (1) {Get-Process | Sort-Object -Descending cpu | Select-Object -First 15 | Format-Table -AutoSize; Start-Sleep 1; Clear-Host}
}
Set-Alias -Name top -value topCmd

function sourceCmd {

    if (Test-Path d:\source) {
        Set-Location -Path d:\Source
    }
}
Set-Alias -name source -value sourceCmd


function dockerhostu1cmd([string]$arguments) {
    $env:docker_host = "tcp://ubuntusrv01.local:2375"
}
Set-Alias -name dockerhostu1 -value dockerhostu1Cmd
function dockerhostu2cmd([string]$arguments) {
    $env:docker_host = "tcp://ubuntusrv02.local:2375"
}
Set-Alias -name dockerhostu2 -value dockerhostu2Cmd

function dockerHostNasCmd([string]$arguments) {
    $env:docker_host = "tcp://nas.local:2375"
}
Set-Alias -name dockerHostNas -value dockerHostNasCmd

function dockerHostlocalCmd([string]$arguments) {
    $env:docker_host = "tcp://localhost:2375"
}
Set-Alias -name DockerHostLocal -value dockerHostlocalCmd

function mcCmd {
    & "C:\Program Files (x86)\Midnight Commander\mc.exe"
}
Set-Alias -name MC -Value mcCmd
function dhCmd {
    # Enter-PSSession -HostName dockhost02.local -UserName lars -SSHTransport
}
Set-Alias -name dh -Value dhCmd

Set-Alias -Name k -Value kubectl
Set-Alias -Name d -Value docker
Set-Alias dc docker-compose

Set-Alias -Name tn -Value Test-NetConnection

function Get-Size {
    param([string]$pth)
    "{0:n2}" -f ((Get-ChildItem -path $pth -recurse -Force | measure-object -property length -sum).sum / 1mb) + " mb"
}

import-module dockercompletion

#$env:PYTHONIOENCODING="utf-8"
#Invoke-Expression "$(thefuck --alias)"

# PowerShell parameter completion shim for the dotnet CLI
Register-ArgumentCompleter -Native -CommandName dotnet -ScriptBlock {
    param($commandName, $wordToComplete, $cursorPosition)
    dotnet complete --position $cursorPosition "$wordToComplete" | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}


function Prompt() {
    $W = Split-Path -leaf -path (Get-Location)
    $prompt = Write-Prompt "$($env:UserName)@$($env:ComputerName):" -ForegroundColor Green
    $prompt += Write-Prompt $W -ForegroundColor DarkCyan
    $prompt += Write-Prompt '>'
    return ' '
}

function Remove-StoppedContainers {
    docker rm $(docker ps -a -q)
}

function Remove-AllContainers {
    docker container rm -f $(docker container ls -aq)
}

function Get-ContainerIPAddress {
    param (
        [string] $id
    )
    & docker inspect --format '{{ .NetworkSettings.Networks.nat.IPAddress }}' $id
}

function Add-ContainerIpToHosts {
    param (
        [string] $name
    )
    $ip = docker inspect --format '{{ .NetworkSettings.Networks.nat.IPAddress }}' $name
    $newEntry = "$ip  $name  #added by d2h# `r`n"
    $path = 'C:\Windows\System32\drivers\etc\hosts'
    $newEntry + (Get-Content $path -Raw) | Set-Content $path
}

#What is my IP address
function myIpCmd {
    Write-Host -ForegroundColor Green (Invoke-WebRequest api.ipify.org).Content
}
Set-Alias -Name myip -Value myIpCmd -Description "Getting my external IP address"


Set-Alias drm  Remove-StoppedContainers
Set-Alias drmf  Remove-AllContainers
Set-Alias dip  Get-ContainerIPAddress
Set-Alias d2h  Add-ContainerIpToHosts

# import-winmodule dism  #Mangler update eller noget efter opdatering til win 1903

import-module z

Set-Theme Paradox

figlet Hello $($env:USERNAME)

function myAnsibleCmd ([string]$parameters) {
    docker run --rm factus/ansible ansible $parameters
}
Set-Alias -Name ans -Value myAnsibleCmd -Description "Ansible in a container"

function myAnsiblePlaybookCmd ([string]$parameters) {
    docker run --rm factus/ansible ansible-playbook $parameters
}
Set-Alias -Name ap -Value myAnsiblePlaybookCmd -Description "Ansible playbook in a container"

$env:VAULT_ADDR = "https://vault.factus.dk"
