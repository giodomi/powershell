<#
.SYNOPSIS
    Exports all VMs in a vCenter/VCF environment along with the NSX-T (Policy)
    Security Groups (Groups) each VM is a member of.

.DESCRIPTION
    - Connects to vCenter via PowerCLI to enumerate VMs.
    - Connects to NSX-T Manager via the NSX-T PowerCLI module (VMware.VimAutomation.Nsxt).
    - Retrieves all NSX Groups (Policy API) and their effective (realized) member VMs,
      which correctly resolves BOTH static VM-based groups AND dynamic
      criteria/tag-based groups.
    - Builds a VM -> [Group1, Group2, ...] map and exports everything to CSV.

.REQUIREMENTS
    - PowerCLI module: VMware.PowerCLI (VimAutomation.Core)
    - PowerCLI module: VMware.VimAutomation.Nsxt
    - Network/API access to vCenter and NSX-T Manager
    - Read permissions on both platforms

.NOTES
    Author: Giovanni Dominoni
    Tested against: NSX-T Policy API (NSX 3.x / 4.x, VCF 5.x/9.x)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$vCenterServer,

    [Parameter(Mandatory = $true)]
    [string]$NsxManager,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$vCenterCredential,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$NsxCredential,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\VM-NSXSecurityGroups-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
)

#region --- Helper: ensure required modules ---
function Ensure-Module {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Warning "Module '$Name' not found. Installing from PSGallery..."
        Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module -Name $Name -ErrorAction Stop
}

Ensure-Module -Name 'VMware.VimAutomation.Core'
Ensure-Module -Name 'VMware.VimAutomation.Nsxt'

# Optional: avoid interactive cert prompts in labs. Comment out in production
# if you want to validate certs properly.
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -ParticipateInCeip $false -Confirm:$false | Out-Null
#endregion

#region --- Connect to vCenter ---
Write-Host "Connecting to vCenter: $vCenterServer" -ForegroundColor Cyan
if ($vCenterCredential) {
    $viConn = Connect-VIServer -Server $vCenterServer -Credential $vCenterCredential -ErrorAction Stop
}
else {
    $viConn = Connect-VIServer -Server $vCenterServer -ErrorAction Stop
}
#endregion

#region --- Connect to NSX-T Manager ---
Write-Host "Connecting to NSX-T Manager: $NsxManager" -ForegroundColor Cyan
if ($NsxCredential) {
    $nsxConn = Connect-NsxtServer -Server $NsxManager -Credential $NsxCredential -ErrorAction Stop
}
else {
    $nsxConn = Connect-NsxtServer -Server $NsxManager -ErrorAction Stop
}

# Policy service handles for Groups
$policyService = Get-NsxtPolicyService -Name "com.vmware.nsx_policy.infra.domains.groups" -Server $nsxConn
$membersService = Get-NsxtPolicyService -Name "com.vmware.nsx_policy.infra.domains.groups.members_vms" -Server $nsxConn

# Domain is typically "default" unless you use multiple NSX domains
$domainId = "default"
#endregion

#region --- Retrieve all VMs from vCenter ---
Write-Host "Retrieving VM inventory from vCenter..." -ForegroundColor Cyan
$allVMs = Get-VM -Server $viConn | Select-Object Name, Id, PowerState, @{N = 'Cluster'; E = { ($_ | Get-Cluster).Name } }

# Build a lookup: External VM Id (as NSX sees it, i.e. instance UUID) -> VM object
# NSX identifies VMs by their vCenter "external_id" (BIOS UUID), not the MoRef.
$vmExternalIdMap = @{}
foreach ($vm in $allVMs) {
    $view = Get-View -Id $vm.Id -Property Config.InstanceUuid
    if ($view.Config.InstanceUuid) {
        $vmExternalIdMap[$view.Config.InstanceUuid] = $vm
    }
}

# Result map: VM Name -> list of Security Group names
$vmGroupMap = @{}
foreach ($vm in $allVMs) {
    $vmGroupMap[$vm.Name] = New-Object System.Collections.Generic.List[string]
}
#endregion

#region --- Retrieve all NSX Groups and their effective VM members ---
Write-Host "Retrieving NSX Security Groups..." -ForegroundColor Cyan
$allGroups = $policyService.list($domainId)

$groupCount = $allGroups.results.Count
$i = 0

foreach ($group in $allGroups.results) {
    $i++
    Write-Progress -Activity "Resolving group membership" -Status "$($group.display_name)" -PercentComplete (($i / $groupCount) * 100)

    try {
        # Effective members resolves BOTH static and dynamic (tag/criteria-based) groups
        $members = $membersService.list($domainId, $group.id)
    }
    catch {
        Write-Warning "Could not resolve members for group '$($group.display_name)': $_"
        continue
    }

    foreach ($member in $members.results) {
        # member.external_id corresponds to the VM's instance UUID
        $matchedVM = $vmExternalIdMap[$member.external_id]
        if ($matchedVM) {
            $vmGroupMap[$matchedVM.Name].Add($group.display_name)
        }
    }
}
Write-Progress -Activity "Resolving group membership" -Completed
#endregion

#region --- Build final export objects ---
Write-Host "Building export data..." -ForegroundColor Cyan
$export = foreach ($vm in $allVMs) {
    $groups = $vmGroupMap[$vm.Name]
    [PSCustomObject]@{
        VMName          = $vm.Name
        PowerState      = $vm.PowerState
        Cluster         = $vm.Cluster
        SecurityGroups  = if ($groups.Count -gt 0) { ($groups | Sort-Object -Unique) -join '; ' } else { '(none)' }
        SecurityGroupCount = ($groups | Sort-Object -Unique).Count
    }
}
#endregion

#region --- Export & cleanup ---
$export | Sort-Object VMName | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "Export complete: $OutputPath" -ForegroundColor Green
Write-Host "$($export.Count) VMs processed, $groupCount NSX groups evaluated." -ForegroundColor Green

Disconnect-NsxtServer -Server $nsxConn -Confirm:$false -ErrorAction SilentlyContinue
Disconnect-VIServer -Server $viConn -Confirm:$false -ErrorAction SilentlyContinue
#endregion
