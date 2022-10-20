<#
.SYNOPSIS
    Automation to reboot Hyper-V nodes within a cluster.
.DESCRIPTION
    Initiate a pause, drain, reboot, and resumption of a Hyper-V node within a cluster. Multiple clusters may be piped to the function, greatly decreasing manual labor for large sites.
.NOTES
    Reach out if something is not working properly.
.LINK
    Specify a URI to a help page, this will show when Get-Help -Online is used.
.EXAMPLE
    ClusterGroup -site <IND | DEN | LHR | FRA> [-ExcludeHV | -ExcludeFS | -ExcludeSQL] [-ForceReboot]
    Options available once functions are loaded.

    ClusterGroup -site IND -ExcludeSQL
    Retrieves clusters in IND region, excluding all SQL clusters.

    ClusterGroup -site YYZ -TargetCluster YYZCluster01
    Retrieves a specific cluster in YYZ region
#>

$Payload_ScriptBlock = {
    param (
        [Parameter(Mandatory = $true, Position = 0)][string]$ClusterName,
        [Parameter(Mandatory = $false, HelpMessage = "Use switch parameter to bypass 'Pending Reboot' check.")]
        [switch]$ForceReboot
    )
    function Write-cmlog {
        [CmdletBinding(SupportsShouldProcess)]
        Param(
            [parameter(Mandatory = $true)]
            [String]$Path,
            [parameter(Mandatory = $true)]
            [String]$Message,
            [parameter(Mandatory = $true)]
            [String]$Component,
            [Parameter(Mandatory = $true)]
            [ValidateSet("Info", "Warning", "Error")]
            [String]$Type,
            [parameter(Mandatory = $false)]
            [int]$MaxLogFileSize = 5MB,
            [parameter(Mandatory = $false)]
            [int]$LogsToKeep = 1,
            [parameter(Mandatory = $false)]
            [int]$Bias = (Get-CimInstance -Query "SELECT Bias FROM Win32_TimeZone").Bias
        )
        begin {
            switch (([System.IO.FileInfo]$Path).Exists <#-and $MaxLogFileSize -gt 0#>) {
                $true {
                    #region rename current file if $MaxLogFileSize exceeded, respecting $LogsToKeep
                    switch (([System.IO.FileInfo]$Path).Length -ge $MaxLogFileSize) {
                        $true {
                            Write-Verbose "switch statement true{} for $path greater than $maxlogfilesize"
                            # Get filename from path
                            [regex]$regex = '^(.*\\)(.*?\..*$)'
                            $Path -match $regex | Out-Null
                            Write-Verbose "Path: $path"
                            $Folder = $matches[1] # First capture group
                            $Filename = $matches[2] # Second capture group
                            Write-Verbose "Folder: $Folder"
                            Write-Verbose "Filename: $Filename"
                            # Get log file name without extension
                            $LogFileNameWithoutExt = $FileName -replace ([System.IO.Path]::GetExtension($FileName))
                            Write-Verbose "LogFileNameWithoutExt: $LogFileNameWithoutExt"
                            # Get already rolled over logs
                            $AllLogs = Get-ChildItem -Path $Folder -File | Where-Object { $_.name -match $($LogFileNameWithoutExt + '_\d+') } #Get-ChildItem -Path $Folder -Name "$($LogFileNameWithoutExt)_*" -File
                            # Sort them numerically (so the oldest is first in the list)
                            $AllLogs = Sort-Object -InputObject $AllLogs -Descending -Property { $_ -replace '_\d+\.lo_$' }, { [int]($_ -replace '^.+\d_|\.lo_$') } -ErrorAction Ignore
                            Write-Verbose "AllLogs: $AllLogs"
                            foreach ($Log in $AllLogs) {
                                Write-Verbose "foreach log: $log"
                                # Get log number
                                $LogFileNumber = [int][Regex]::Matches($Log, "_([0-9]+)\.lo_$").Groups[1].Value
                                Write-Verbose "LogFileNumber: $LogFileNumber"
                                switch (($LogFileNumber -eq $LogsToKeep) -and ($LogsToKeep -ne 0)) {
                                    $true {
                                        # Delete log if it breaches $LogsToKeep parameter value
                                        [System.IO.File]::Delete("$($Folder)\$($Log)")
                                    }
                                    $false {
                                        # Rename log to +1
                                        $NewFileName = $Log -replace "_([0-9]+)\.lo_$", "_$($LogFileNumber+1).lo_"
                                        Write-Verbose "$($Folder)\$($Log) -> $($Folder)\$($NewFileName)"
                                        [System.IO.File]::Copy("$($Folder)\$($Log)", "$($Folder)\$($NewFileName)", $true)
                                    }
                                }
                            }
                            # Copy main log to _1.lo_
                            Write-Verbose "Rolling over log to '$($LogFileNameWithoutExt)_1.lo_' as MaxLogFileSize of '$MaxLogFileSize' reached."
                            [System.IO.File]::Copy($Path, "$($Folder)\$($LogFileNameWithoutExt)_1.lo_", $true)
                            # Blank the main log
                            $StreamWriter = New-Object -TypeName System.IO.StreamWriter -ArgumentList $Path, $false
                            $StreamWriter.Close()
                        }
                    }
                    #endregion rename current file if $MaxLogFileSize exceeded, respecting $LogsToKeep
                }
            }
            # CMLog message type
            switch ($Type) {
                "Info" { [int]$Type = 1 }
                "Warning" { [int]$Type = 2 }
                "Error" { [int]$Type = 3 }
            }
            # write-host message color for type
            switch ($type) {
                "Warning" { $color = @{ForegroundColor = 'Yellow' } }
                "Error" { $color = @{ForegroundColor = 'Red' } }
                default { $color = @{ForegroundColor = 'White' } }
            }
            # Construct date for log entry
            $Date = (Get-Date -Format 'MM-dd-yyyy')
            # Construct context for log entry
            $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        } # END OF begin{}
        process {
            #region construct time stamp for log entry based on $Bias and current time
            $Time = switch -regex ($Bias) {
                '-' {
                    [string]::Concat($(Get-Date -Format 'HH:mm:ss.fff'), $Bias)
                }
                Default {
                    [string]::Concat($(Get-Date -Format 'HH:mm:ss.fff'), '+', $Bias)
                }
            }
            #endregion construct time stamp for log entry based on $Bias and current time
            #region construct the log entry according to CMTrace format
            $LogText = [string]::Format('<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="{4}" type="{5}" thread="{6}" file="">', $MSG, $Time, $Date, $Component, $Context, $LogLevel, $PID)
            #endregion construct the log entry according to CMTrace format
            # Create a log entry
            $Content = "<![LOG[$Message]LOG]!>" + `
                "<time=`"$(Get-Date -Format "HH:mm:ss.ffffff")`" " + `
                "date=`"$(Get-Date -Format "M-d-yyyy")`" " + `
                "component=`"$Component`" " + `
                "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + `
                "type=`"$Type`" " + `
                "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " + `
                "file=`"`">"
            Write-Host "$message" @color
            # Write the line to the log file
            $PriorPreference = $ErrorActionPreference
            $ErrorActionPreference = "Stop"
            try {
                # Use Mutex to avoid write lock
                $LogMutex = New-Object System.Threading.Mutex($false, "LogMutex")
                $LogMutex.WaitOne() | Out-Null
                #$Content | out-file -FilePath $Path -Append
                Add-Content -Path $Path -Value $Content -ErrorAction SilentlyContinue
                $LogMutex.ReleaseMutex() | Out-Null
            } catch {
                # Fall back to tried and true if Mutex fails.
                Start-Sleep -Milliseconds $(Get-Random -Minimum 50 -Maximum 200) # Randomize sleep if we encounter an error during add-content due to file access contention.
                Add-Content -Path $Path -Value $Content -ErrorAction SilentlyContinue #If we're writing a lot to a file, suppress the error so we don't send an error downstream
            } finally {
                $ErrorActionPreference = $PriorPreference
            }
        }  
    }
    function checkcluster {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
            $Cluster,
            [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
            [string]$Name)
        $output = Get-ClusterNode @PSBoundParameters
        return $output
    }
    # Set defaults for function:\write-cmlog
    $PSDefaultParameterValues = @{
        'write-cmlog:path'      = "C:\Windows\Temp\$ClusterName`_DrainReboot.log"
        'write-cmlog:Component' = 'Script'
        'write-cmlog:type'      = 'Info'
    }
    #$VerbosePreference = "Silentlycontinue"
    write-cmlog -message "Cluster [$ClusterName]"
    #[regex] $a_regex = '(?i)^(' + (($ExcludeServers | ForEach-Object { [regex]::escape($_) }) -join "|") + ')$'
    $Nodes = checkcluster $ClusterName
    #TODO Check that this actually resumes nodes and add verification.
    if ($nodes.state -match 'Paused') {
        write-cmlog -message "Node(s) were found paused. $($nodes | Where-Object{$_.state -eq 'Paused'})."
        $nodes | Format-Table -AutoSize | Out-Host
        foreach ($node in $nodes | Where-Object { $_.state -eq 'Paused' }) {
            write-cmlog -message "Resuming $($Node.name)..."
            Resume-ClusterNode -Cluster $clustername -Name $node.name | Out-Null
        }
        $nodes = checkcluster $ClusterName
        $nodes | Format-Table -AutoSize | Out-Host
        Read-Host "Please check that all looks good now. Press any key to continue..."
    }
    if ($nodes.state -match '(Down)') {
        write-cmlog -Message "Unable to proceed as nodes were already found down. $($nodes | Where-Object{$_.state -eq 'Down'})" -type Warning
        $($nodes | Format-Table -AutoSize) | Out-Host
        $choice = Read-Host "Nodes were found down in $clustername. Do you wish to continue? Y or N"
        if ($choice -match '(?i)Y') {} else { break }
    }

    $host.ui.RawUI.WindowTitle = "$clustername - Running"
    Write-Host "There are $($nodes.count) nodes in the cluster."
    foreach ($Node in $Nodes) {
        if ($Node.State -eq "Up") {
            # Retrieve last reboot time
            $b = Get-WmiObject win32_operatingsystem -computername $node.name | Select-Object @{LABEL = 'LastBootUpTime'; EXPRESSION = { $_.ConverttoDateTime($_.lastbootuptime) } }
            $CCMSplat = @{
                NameSpace    = 'ROOT\ccm\ClientSDK'
                Class        = 'CCM_ClientUtilities'
                Name         = 'DetermineIfRebootPending'
                ComputerName = $node.name
                ErrorAction  = 'SilentlyContinue'
            }
            # Evaluate if there's a pending reboot utilizing CM's ClientSDK WMIC NameSpace
            $c = Invoke-WmiMethod @CCMSplat
            # Set High Performance Power Plan on node, regardless of reboot status.
            Invoke-Command -ComputerName $node.name -ScriptBlock {
                & powercfg.exe -SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
            }
            if ($($node.name -match '(HV)')) {
                # Fix VM version for meltdown and remove attached ISOs.
                Invoke-Command -ComputerName $node.name -command { 
                    & reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" /v MinVmVersionForCpuBasedMitigations /t REG_SZ /d "1.0" /f | Out-Null
                    #Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object { Set-ItemProperty -Path $_.pspath -Name 'NetbiosOptions' -Value '1' } | Out-Null
                    get-vm -ErrorAction SilentlyContinue | Get-VMDvdDrive -ErrorAction SilentlyContinue | Set-VMDvdDrive -ErrorAction SilentlyContinue | Out-Null # Remove those pesky ISO mounts.
                }
            }
            # If there are no pending reboots, and node has been rebooted within the last 30 days, and we're not forcing a reboot via '-ForceReboot', move on to next node
            if ($c.RebootPending -eq $false -and $b.lastbootuptime -ge (Get-Date).adddays(-30) -and $PSBoundParameters.ContainsKey('ForceReboot') -eq $false) {
                Write-cmlog -message "$($node.name) indicates that it has no pending reboots. Moving on to next node. LastBootUpTime: $($b.lastbootuptime)" -type 'Warning'
                continue
            }
            write-cmlog -message "Pausing Host [$($node.name)] and draining roles. LastBootUpTime: $($b.lastbootuptime)"
            # Suspend-ClusterNode cannot be executed remotely, which is likely what we'd be doing. Invoke the command on the remote server instead
            Invoke-Command -ComputerName $node.name -command { suspend-clusternode -drain -wait -ErrorAction SilentlyContinue } 
            Start-Sleep -s 5
            $NodeStatus = checkcluster $clustername $node
            if (($NodeStatus.DrainStatus -ne "Completed")) {
                write-cmlog -message "Initial drain of [$Node] was not successful. Trying one more time before user intervention is required." -Type 'Warning'
                Invoke-Command -ComputerName $node.name -command { suspend-clusternode -drain -wait -ErrorAction SilentlyContinue } 
                Start-Sleep -s 2
                $NodeStatus = checkcluster $clustername $node
                if ($NodeStatus.DrainStatus -ne "Completed") {
                    $host.ui.RawUI.WindowTitle = "$clustername - PAUSED"
                    write-cmlog -message "Check of [$Node]'s drain status indicates the operation was not successful." -Type 'Error'
                    while (($NodeStatus.DrainStatus -ne "Completed")) {
                        Write-Warning "Log on to the node to determine why the drain failed. This could be due to VM roles not Live Migrating."
                        Read-Host "Pause the node within FCM, then press [Enter] key to recheck, or press [Ctrl-C] to stop the script"
                        $NodeStatus = checkcluster $clustername $node
                    }
                }
            }
            $host.ui.RawUI.WindowTitle = "$clustername - RUNNING"
            if (($NodeStatus.DrainStatus -eq "Completed") -and ($NodeStatus.State -eq "Paused")) {
                write-cmlog -message "($ClusterName) || Host [$Node] is paused"
                # VMM check. If it's present, we will drain node and remove VMM.
                $RemoveProg = $null
                $RemoveProg = get-wmiobject win32reg_addremoveprograms -computername $node.name | Where-Object { $_.displayname -match 'System Center Virtual Machine Manager|Veeam' }
                if ($RemoveProg) {
                    write-cmlog -message "Found programs to remove, uninstalling them now" -type Warning
                    $Erroractionpreference = "Stop"
                    try {
                        Invoke-Command -ComputerName $node.name -ScriptBlock {
                            $RemoveProg = get-wmiobject win32reg_addremoveprograms | Where-Object { $_.displayname -match 'System Center Virtual Machine Manager|Veeam' }
                            foreach ($item in $RemoveProg) {
                                Start-Process "msiexec.exe" -ArgumentList "/x $($item.ProdID) /qn /norestart /L+ C:\Windows\Temp\$( $item.displayname -replace " ","_" )_Uninstall.log" -Wait 
                            }
                        }
                    } catch {
                        write-cmlog -message "Error encountered attempting to uninstall $($item.displayname). The error was $($error[0].Exception.message)" -type Error
                    } finally {
                        $Erroractionpreference = "Continue"
                    }
                }
                write-cmlog -message "Rebooting Host [$Node] and waiting for it to come online..."
                Restart-Computer -ComputerName $Node.Name -Force -Wait -For PowerShell -Delay 15
                # Number of cycles to evaluate before determining node's cluster services haven't resumed.
                [int]$WaitCount = 0
                [int]$WaitTimer = 120
                write-cmlog -message "Host [$Node] is online. Waiting up to $WaitTimer seconds for node's membership state to change from 'Down' to 'Paused' so we may resume"
                # Check if node state is down, waiting until $WaitTimer
                Do {
                    $WaitCount++
                    $NodeStatus = checkcluster $clustername $node
                    Start-Sleep -s 1
                } while ($NodeStatus.State -eq "Down" -and $WaitCount -le $WaitTimer)
                # Cluster service did not properly start within the defined time limit, meaning something bad happened. Inform the user to take action.
                if ($NodeStatus.State -eq "Down" -and $WaitCount -ge $WaitTimer) {
                    Write-cmlog -message "$WaitTimer seconds has elapsed and node indicates it is 'Down' for cluster participation. Prompting the user to take action." -type 'Error'
                    # Check specifically for state being 'Down' and block user from continuing until it is resolved.
                    while ($NodeStatus.State -eq "Down") {
                        Write-Warning "[$Node] indicates it is 'Down' for cluster participation. Please investigate and manually resume."
                        Read-Host "Press any key to recheck node's state."
                        $NodeStatus = checkcluster $clustername $node
                    }
                }
                # This will only ever be evaluated if our previous if{} statement was encountered.
                if ($NodeStatus.State -eq 'Up') {
                    write-cmlog -message "Host [$Node] is now active"
                    # Move on to next node as it is already up in cluster.
                    continue
                }
                # Resume node in the cluster
                write-cmlog -message "Attempting to resume [$Node]..."
                Resume-ClusterNode -Name $Node.Name -Cluster $ClusterName
                Start-Sleep -s 3
                $NodeStatus = checkcluster $clustername $node
                if ($NodeStatus.State -ne "Up") {
                    write-cmlog -message "The node [$Node] did not indicate it was marked 'Up' within the cluster. Please check its status in FCM. Prompting the user to take action." -type 'Error'
                    while ($NodeStatus.State -ne "Up") {
                        Write-Warning "[$Node] indicates it is not 'Up' within the cluster. Please manually resume it in the cluster."
                        Read-Host "Press any key to recheck node's state."
                        $NodeStatus = checkcluster $clustername $node
                    }
                }
                Start-Sleep -s 5
                write-cmlog -message "Host [$Node] is now active"
            }
        } elseif ($node.state -eq "Down") {
            write-cmlog -message "Host [$Node] is Down! Skipping it"
            continue
        }
    }
    $host.ui.RawUI.WindowTitle = "$clustername - DONE"
}

function ClusterGroup {
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Region to reboot nodes in.")]
        [ValidateSet("IND", "DEN", "LHR", "FRA", "YUL", "YYZ")]
        $site,
        [Parameter(Mandatory = $false, HelpMessage = "Specify a specific cluster to target in region")]
        $TargetCluster,
        [Parameter(Mandatory = $false, HelpMessage = "Comma delimited array of clusters to not include.")]
        [array]$ExcludeCluster,
        [Parameter(HelpMessage = "Switch to exclude Hyper-V Clusters from list.")]
        [switch]$ExcludeHV,
        [Parameter(HelpMessage = "Switch to exclude Fileserver Clusters from list.")]
        [switch]$ExcludeFS,
        [Parameter(HelpMessage = "Switch to exclude SQL Clusters from list.")]
        [switch]$ExcludeSQL,
        [Parameter(Mandatory = $false, HelpMessage = "Use switch parameter to bypass 'Pending Reboot' check. This does NOT force nodes to reboot that fail to drain.")]
        [switch]$ForceReboot
    )
    # 
    # Filter script for where-object
    [array]$filterscript = "`${psitem}.name -match '$site' -and `${psitem}.id -ne `${null} "
    switch ($PSBoundParameters.Keys) {
        'ExcludeHV' { $filterscript += " `${psitem}.name -notmatch 'HV'" }
        'ExcludeFS' { $filterscript += " `${psitem}.name -notmatch 'FS|RF'" }
        'ExcludeSQL' { $filterscript += " `${psitem}.name -notmatch 'SQ'" }
        default {}
    }
    if ($PSBoundParameters.ContainsKey('TargetCluster')) {
        $filterscript += " `${psitem}.name -match '${TargetCluster}'"
    }
    if ($PSBoundParameters.ContainsKey('ExcludeCluster')) {
        foreach ($item in $ExcludeCluster) {
            $filterscript += " `${psitem}.name -ne '$item'"
        }
    }
    # Build conditional for each item in our array
    $filterscript_join = "$($filterscript -join '-and')"
    # Create scriptblock that we will use for where-object's filterscript
    $scriptblock = [scriptblock]::create( "$filterscript_join" )
    $Clusters = get-cluster -domain $env:USERDNSDOMAIN | Where-Object $scriptblock
    Write-Host "Below are the clusters and nodes to be rebooted."
    if ($PSBoundParameters.ContainsKey('ForceReboot')) {
        Write-Warning "'-ForceReboot' switch specified. Nodes will be rebooted regardless if there's no pending reboots."
    }
    $Clusters | Format-Table
    $clusters | get-clusternode | Select-Object name, id, state, cluster | Sort-Object cluster, name | Format-Table
    Read-Host "Press any key to continue"
    foreach ($cluster in $clusters.name) {
        $GUID = New-Guid
        $arglist = "-ClusterName $Cluster"
        if ($PSBoundParameters.ContainsKey('ForceReboot')) {
            $arglist += " -ForceReboot"
        }
        $TempScript = ("${env:temp}\${GUID}.ps1")
        # Create self deleting script file
        @"
$Payload_ScriptBlock
Remove-Item `$PSCommandPath
"@ > $tempScript
        Start-Process powershell -ArgumentList '-NoExit', '-NoProfile', '-File', $tempScript, $arglist
    }
}