# PowerShell - как глянуть, кто и когда подключался по RDP
```
$RDPAuths = Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -FilterXPath '<QueryList><Query Id="0"><Select>*[System[EventID=1149]]</Select></Query></QueryList>'
[xml[]]$xml=$RDPAuths|Foreach{$_.ToXml()}
$EventData = Foreach ($event in $xml.Event)
{ New-Object PSObject -Property @{
TimeCreated = (Get-Date ($event.System.TimeCreated.SystemTime) -Format 'yyyy-MM-dd hh:mm:ss K')
User = $event.UserData.EventXML.Param1
Domain = $event.UserData.EventXML.Param2
Client = $event.UserData.EventXML.Param3
}
} $EventData | FT
```


# Полный скрипт для вывода журнала RDP-подключений

```
# Показывает историю RDP-подключений: успешные, неуспешные, reconnect
# Требует запуск от имени администратора

$events4624 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -ErrorAction SilentlyContinue
$events4625 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -ErrorAction SilentlyContinue
$events1149 = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=1149} -ErrorAction SilentlyContinue

$allEvents = @()

foreach ($ev in $events1149) {
    $xml = [xml]$ev.ToXml()
    $allEvents += [PSCustomObject]@{
        TimeCreated = $ev.TimeCreated
        EventID     = 1149
        User        = $xml.Event.EventData.Data[1]
        IP          = $xml.Event.EventData.Data[3]
        Status      = "RDP Authentication Success"
    }
}

foreach ($ev in $events4624) {
    $xml = [xml]$ev.ToXml()
    $logonType = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'} | Select-Object -Expand '#text'

    if ($logonType -eq 10) {
        $ip = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -Expand '#text'
        $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -Expand '#text'
        $allEvents += [PSCustomObject]@{
            TimeCreated = $ev.TimeCreated
            EventID     = 4624
            User        = $user
            IP          = $ip
            Status      = "Successful RDP Logon"
        }
    }
}

foreach ($ev in $events4625) {
    $xml = [xml]$ev.ToXml()
    $ip = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -Expand '#text'
    $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -Expand '#text'
    $allEvents += [PSCustomObject]@{
        TimeCreated = $ev.TimeCreated
        EventID     = 4625
        User        = $user
        IP          = $ip
        Status      = "Failed Logon (likely RDP)"
    }
}

$allEvents | Sort-Object TimeCreated | Format-Table -AutoSize

```
# Короткая версия (только успешные логины + IP)

```
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    if ($xml.Event.EventData.Data[8] -eq "10") {   # LogonType 10 = RDP
        [PSCustomObject]@{
            Time = $_.TimeCreated
            User = $xml.Event.EventData.Data[5]
            IP   = $xml.Event.EventData.Data[18]
        }
    }
} | Format-Table

```
