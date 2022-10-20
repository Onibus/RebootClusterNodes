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