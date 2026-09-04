<#
.SYNOPSIS
    Emit correctly-formed sample log lines for each supported ULPF source and
    send them to a UDP listener (default syslog port 514).

.DESCRIPTION
    Hand-typed test lines are a reliable way to break the pipeline. This script
    is the canonical generator — the templates below match the fixtures under
    tests/fixtures/ and every source's `detect` + `normalize` rules.

    FortiGate in particular sends a BARE PRI: `<189>` immediately followed by
    `date=... time=...`, with NO RFC 3164 timestamp and NO hostname. Inserting
    `Oct 11 22:14:15 fg1` after the PRI makes the syslog envelope parser consume
    `date=2019-05-10` as the syslog TAG, which breaks the date+time timestamp
    join. Do not do that. The FortiGate template here is bare-PRI.

.PARAMETER Source
    cisco_asa | fortigate_traffic (alias: fortigate) | panos (alias:
    panos_traffic) | suricata (alias: suricata_eve) | zeek (alias: zeek_conn) |
    iptables

.PARAMETER Count
    How many lines to emit (each is made distinct by an index). Default 1.

.PARAMETER Port
    Destination UDP port. Default 514.

.PARAMETER TargetHost
    Destination host. Default 127.0.0.1.

.PARAMETER DryRun
    Print the lines instead of sending them.

.EXAMPLE
    .\scripts\win\send-sample.ps1 -Source fortigate_traffic -Count 5 -Port 5514

.EXAMPLE
    .\scripts\win\send-sample.ps1 -Source zeek -DryRun
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet(
        'cisco_asa',
        'fortigate_traffic', 'fortigate',
        'panos', 'panos_traffic',
        'suricata', 'suricata_eve',
        'zeek', 'zeek_conn',
        'iptables'
    )]
    [string]$Source,

    [int]$Count = 1,
    [int]$Port = 514,
    [string]$TargetHost = '127.0.0.1',
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# alias -> canonical source name
$canonical = @{
    'fortigate'      = 'fortigate_traffic'
    'panos_traffic'  = 'panos'
    'suricata_eve'   = 'suricata'
    'zeek_conn'      = 'zeek'
}
if ($canonical.ContainsKey($Source)) { $Source = $canonical[$Source] }

function Oct([int]$base, [int]$i) { return $base + ($i % 200) }   # keep IPv4 octet <= 254

# Each template is a scriptblock: param($i) -> one well-formed line (string).
$templates = @{

    # RFC 3164 syslog + grok body.
    'cisco_asa' = {
        param($i)
        $sp = 51234 + $i
        "<134>Oct 11 22:14:15 fw01 %ASA-6-302013: Built outbound TCP connection " +
        "$(12345 + $i) for outside:203.0.113.9/443 (203.0.113.9/443) to " +
        "inside:192.0.2.$(Oct 15 $i)/$sp (198.51.100.7/$sp)"
    }

    # BARE PRI, then key=value. No RFC 3164 stamp, no hostname.
    'fortigate_traffic' = {
        param($i)
        $ss = '{0:d2}' -f (48 + ($i % 12))
        '<189>date=2019-05-10 time=11:50:' + $ss + ' devname="FGT60F" ' +
        'devid="FGT60FTK20000001" logid="0000000013" type="traffic" ' +
        'subtype="forward" srcip=10.20.30.' + (Oct 40 $i) + ' srcport=' + (62024 + $i) +
        ' dstip=203.0.113.99 dstport=3389 proto=6 action="deny" policyid=9 ' +
        'sentbyte=120 rcvdbyte=0'
    }

    # RFC 5424 header + headerless PAN-OS TRAFFIC CSV (10.x = 47 fields).
    'panos' = {
        param($i)
        $sid = 104512 + $i
        $sp  = 51234 + $i
        '<14>1 2026-09-01T12:00:03Z pa-fw1 - - - - ' +
        "1,2026/09/01 12:00:03,001801234567,TRAFFIC,end,2622,2026/09/01 12:00:00," +
        "192.0.2.$(Oct 15 $i),203.0.113.9,198.51.100.7,203.0.113.9,allow-web,,,ssl," +
        "vsys1,trust,untrust,ethernet1/2,ethernet1/1,forward-all,,$sid,1,$sp,443," +
        "51235,443,0x400053,tcp,allow,5060,1240,3820,12,2026/09/01 11:59:48,12," +
        "web-advertisements,0,7000000123,0x0,192.0.2.0-192.0.2.255,United States,0,7,5,tcp-fin"
    }

    # Suricata EVE JSON (event_type=flow -> OCSF 4001). No syslog framing.
    'suricata' = {
        param($i)
        $fid = 1234567890 + $i
        $sp  = 51234 + $i
        '{"timestamp":"2026-08-15T22:14:35.500000+0000","flow_id":' + $fid +
        ',"in_iface":"eth0","event_type":"flow","src_ip":"192.0.2.' + (Oct 15 $i) +
        '","src_port":' + $sp + ',"dest_ip":"203.0.113.9","dest_port":443,"proto":"TCP",' +
        '"app_proto":"tls","flow":{"pkts_toserver":14,"pkts_toclient":12,' +
        '"bytes_toserver":1800,"bytes_toclient":4300,' +
        '"start":"2026-08-15T22:14:20.001000+0000","end":"2026-08-15T22:14:35.400000+0000",' +
        '"age":15,"state":"closed","reason":"timeout","alerted":false},' +
        '"tcp":{"tcp_flags":"1e","syn":true,"fin":true,"ack":true,"state":"closed"}}'
    }

    # Zeek conn.log in JSON mode (literal dotted keys). No syslog framing.
    'zeek' = {
        param($i)
        $sp = 51234 + $i
        '{"ts":1697062455.123456,"uid":"C' + ('{0:x8}' -f (0x5a8b0000 + $i)) +
        '","id.orig_h":"192.0.2.' + (Oct 15 $i) + '","id.orig_p":' + $sp +
        ',"id.resp_h":"203.0.113.9","id.resp_p":443,"proto":"tcp","service":"ssl",' +
        '"duration":12.34,"orig_bytes":1240,"resp_bytes":3820,"conn_state":"SF",' +
        '"local_orig":true,"local_resp":false,"missed_bytes":0,"history":"ShADadFf",' +
        '"orig_pkts":14,"orig_ip_bytes":1800,"resp_pkts":12,"resp_ip_bytes":4300,' +
        '"tunnel_parents":[]}'
    }

    # iptables / netfilter kernel log (RFC 3164 syslog, key=VALUE body).
    'iptables' = {
        param($i)
        $sp = 44321 + $i
        '<4>Sep  2 10:15:32 gw kernel: act=drop chain=INPUT rule=90 IN=eth0 OUT= ' +
        'MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 SRC=203.0.113.' + (Oct 45 $i) +
        ' DST=192.0.2.10 LEN=60 TOS=0x00 PREC=0x00 TTL=54 ID=' + (54321 + $i) +
        ' DF PROTO=TCP SPT=' + $sp + ' DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0'
    }
}

$template = $templates[$Source]
$client = if ($DryRun) { $null } else { New-Object System.Net.Sockets.UdpClient }
try {
    for ($i = 0; $i -lt $Count; $i++) {
        $line = & $template $i
        if ($DryRun) {
            Write-Output $line
        }
        else {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($line)
            [void]$client.Send($bytes, $bytes.Length, $TargetHost, $Port)
            Write-Verbose ("sent {0}:{1}  {2}" -f $TargetHost, $Port, $line)
        }
    }
    if (-not $DryRun) {
        Write-Host ("sent {0} {1} line(s) to {2}:{3}" -f $Count, $Source, $TargetHost, $Port)
    }
}
finally {
    if ($client) { $client.Close() }
}
