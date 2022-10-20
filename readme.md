# Getting Started

To get started, follow instructions in section **Download** and **Quickstart**. Codeblocks within these sections are safe to copy and paste, requiring only minor modifications when called out.

Commands should be ran from elevated Powershell.

# Download

Retrieve latest version of the script and load functions for session.

```powershell
remove-item $env:userprofile\desktop\RebootClusterNodes.ps1 -erroraction silentlycontinue; Invoke-WebRequest -URI 'https://raw.githubusercontent.com/Onibus/RebootClusterNodes/main/RebootClusterNode.ps1' -OutFile $env:userprofile\desktop\RebootClusterNodes.ps1; . $env:userprofile\desktop\RebootClusterNodes.ps1
```

# Quickstart

At its most basic, we can specify a region with the parameter `-site` to get started, replacing `<region>` with the three-letter site.

```powershell
ClusterGroup -site <region>
```

A list of clusters and its nodes will appear.

If the cluster list looks correct, press any key to proceed.

A number of windows will open, each corresponding to the cluster being processed.

The operation status for each cluster will be reflected within the window’s titlebar. You may be prompted to intervene and address issues that prevent the script from continuing, such as acknowledging nodes that are down or troubleshooting nodes that fail to drain. The script will inform you of the failure and action to take.

# ClusterGroup Function

`ClusterGroup` is a function that’s loaded within our session. Its purpose is to kickstart the reboot process for a given region.

Below are available parameters:

```powershell
ClusterGroup [-site] {IND | DEN | LHR | FRA | YUL | YYZ} [[-TargetCluster] <Object>] [[-ExcludeCluster] <array>]
    [-ExcludeHV] [-ExcludeFS] [-ExcludeSQL] [-ForceReboot]
```

| Command | Description |
| --- | --- |
| `-site <region>` | Return a list of clusters within that region. |
| `-TargetCluster <cluster>` | Comma delimited list of clusters to return for processing, useful to rerun ClusterGroup against specified cluster(s) that have completed their reboots while others in the region are ongoing. |
| `-ExcludeCluster <cluster>` | Comma delimited list of clusters to exclude, useful for excluding clusters in a state of decomission. |
| `-Exclude[HV\|FS\|SQL]` | Exclude respective cluster role from list. |
| `-ForceReboot` | Bypass “pending reboot” check, rebooting the node. Does NOT force a node to reboot if there are drain failures. This switch should not be used unless directed to or for good reason. |

## Examples

### Reboot all clusters in IND region

```powershell
ClusterGroup -site IND
```

### Reboot specific cluster in IND region

```powershell
ClusterGroup -site IND -TargetCluster INDCSPRHV123
```

### Reboot specific clusters in IND region

```powershell
ClusterGroup -site IND -TargetCluster INDCSPRHV123,INDCSPRSQ123
```

### Reboot all clusters in IND region, excluding INDCSPRHV123 and INDCSPRSQ123

```powershell
ClusterGroup -site IND -ExcludeCluster INDCSPRHV123,INDCSPRSQ123
```

### Reboot all clusters in IND region, excluding SQL and Fileserver clusters

```powershell
ClusterGroup -site IND -ExcludeSQL -ExcludeFS
```
# Additional codeblocks

These are additional codeblocks that are useful, but only when required. Please ignore these as you do not need to run these.
```powershell
<#
foreach ($node in $(get-clusternode | Select-Object -ExpandProperty name)) {
    Invoke-Command -ComputerName $node -ScriptBlock {
        write-host "Working on $env:computername"
        write-host "Setting $false for RequireSecuritySignature"
        Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
        #write-host "Adjusting NetBIOS option for NICs"
        #Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object { Set-ItemProperty -Path $_.pspath -Name 'NetbiosOptions' -Value '1' }
    }
}
#>

<#function postconfig {
    param($site = $null)
    if ($site -eq $null) {
        return
    }
    $clusters = get-cluster -domain $env:USERDNSDOMAIN | Where-Object { $_.name -match $site -and $_.name -notmatch 'SQ|HV11|FS' -and $_.id -ne $null }
    Write-Host "Below are the clusters"
    $Clusters | Format-Table
    Read-Host "Press any key to continue"
    foreach ($cluster in $clusters) {
        Write-Host "Working on $cluster"
        get-clusternode -cluster $cluster | Where-Object { $_.state -ne 'Down' } | Select-Object name | ForEach-Object {
            Write-Host "Setting High Perf Power Plan on $($_.name) of $cluster"
            Invoke-Command -ComputerName $_.name -command { & powercfg.exe -SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c }
        }
        if ($((Get-Cluster -name $cluster).BlockCacheSize) -ne '8192') {
        Write-Host "Setting blocksize..."
        (Get-Cluster -name $cluster).BlockCacheSize = '8192'
        Write-Host "Moving CSVs of $cluster..."
        #get-clustersharedvolume -cluster $cluster | move-clustersharedvolume
        }
        write-host "Migrating VMs around"
        # This requires credssp to run, so we invoke-command.
        #invoke-command -computername $cluster -command {get-clustergroup | ?{$_.grouptype -eq 'VirtualMachine' -and $_.name -notmatch 'GFS' -and $_.state -eq 'Online'} | Move-ClusterVirtualMachineRole -wait 0}
    }
}#>
```