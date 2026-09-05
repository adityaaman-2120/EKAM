<#
.SYNOPSIS
    Emit correctly-formed sample log lines for each supported ULPF source and
    send them to a syslog listener (default port 514, TCP).

.DESCRIPTION
    Hand-typed test lines are a reliable way to break the pipeline. This script
    is the canonical generator — the templates below match the fixtures under
    tests/fixtures/ and every source's `detect` + `normalize` rules.

    FortiGate in particular sends a BARE PRI: `<189>` immediately followed by
    `date=... time=...`, with NO RFC 3164 timestamp and NO hostname. Inserting
    `Oct 11 22:14:15 fg1` after the PRI makes the syslog envelope parser consume
    `date=2019-05-10` as the syslog TAG, which breaks the date+time timestamp
    join. Do not do that. The FortiGate template here is bare-PRI.

    -Source accepts any source definition name under configs/sources/ (checked
    dynamically at run time, so this script can never silently drift from the
    registry) plus a handful of short aliases for the sources most often used
    in manual testing. Run with -List to see every currently-supported name.

    TRANSPORT AND LOSS. UDP syslog is lossy by design — no handshake, no
    acknowledgement, no retransmission — and blasting a burst with no pacing
    routinely overflows the kernel receive buffer (10-30%+ loss at a few
    thousand events/sec is typical). That silently distorts every downstream
    measurement (sealed count, per-source normalization rate) into an artifact
    of the transport, not a fact about the pipeline. -Transport therefore
    defaults to `tcp`: reliable, in-order delivery, so "sent" and "received"
    are the same number. Pass `-Transport udp` only when the point of the run
    IS to exercise UDP loss behaviour itself. -RateEps paces sends for either
    transport (mainly useful to keep a UDP receive buffer from ever filling).

.PARAMETER Source
    A source definition name from configs/sources/, or one of the aliases:
    fortigate (-> fortigate_traffic), suricata (-> suricata_eve_flow), zeek
    (-> zeek_conn), panos (-> panos_traffic_v10). Not required when -List is
    given.

.PARAMETER Count
    How many lines to emit (each is made distinct by an index). Default 1.

.PARAMETER Transport
    `tcp` (default) or `udp`. TCP frames each line with RFC 6587
    octet-counting (`MSGLEN SP MSG`) over one persistent connection, matching
    what ulpf's syslog TCP listener expects. Default `tcp` because lossless
    delivery should be the default for verification runs — see DESCRIPTION.

.PARAMETER RateEps
    Pace sending to at most this many events per second, instead of blasting
    as fast as the loop can go. 0 (default) means unpaced.

.PARAMETER Report
    Print sent count, elapsed time, and the achieved rate (events/sec) after
    sending.

.PARAMETER Port
    Destination port. Default 514.

.PARAMETER TargetHost
    Destination host. Default 127.0.0.1.

.PARAMETER DryRun
    Print the lines instead of sending them.

.PARAMETER List
    Print every source name this script can generate and exit (no -Source
    needed).

.EXAMPLE
    .\scripts\win\send-sample.ps1 -Source fortigate_traffic -Count 5 -Port 5514

.EXAMPLE
    .\scripts\win\send-sample.ps1 -Source zeek -DryRun

.EXAMPLE
    .\scripts\win\send-sample.ps1 -List

.EXAMPLE
    # verification run: lossless TCP, paced, with a summary
    .\scripts\win\send-sample.ps1 -Source cisco_asa -Count 300 -RateEps 200 -Report
#>
[CmdletBinding()]
param(
    [ValidateScript({
        # Deliberately re-derived from configs/sources/*.yaml on every run
        # (not a hard-coded ValidateSet) so this script can never drift from
        # the actual registry the way it did before: it once accepted
        # "suricata_eve" when the real definition was named suricata_eve_alert.
        $sourcesDir = Join-Path $PSScriptRoot '..\..\configs\sources'
        $names = Get-ChildItem $sourcesDir -Filter '*.yaml' | ForEach-Object {
            $match = Select-String -Path $_.FullName -Pattern '^name:\s*(\S+)' | Select-Object -First 1
            if ($match) { $match.Matches[0].Groups[1].Value }
        }
        $aliases = @('fortigate', 'suricata', 'zeek', 'panos')
        if (($names + $aliases) -contains $_) {
            return $true
        }
        throw "'$_' is not a known source. Valid names: $(($names | Sort-Object) -join ', '). " +
            "Aliases: $($aliases -join ', '). Run with -List to see this again."
    })]
    [string]$Source,

    [int]$Count = 1,
    [ValidateSet('tcp', 'udp')]
    [string]$Transport = 'tcp',
    [int]$RateEps = 0,
    [switch]$Report,
    [int]$Port = 514,
    [string]$TargetHost = '127.0.0.1',
    [switch]$DryRun,
    [switch]$List
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-UlpfSourceNames {
    <# Every source definition name declared under configs/sources/*.yaml. #>
    $sourcesDir = Join-Path $PSScriptRoot '..\..\configs\sources'
    Get-ChildItem $sourcesDir -Filter '*.yaml' | ForEach-Object {
        $match = Select-String -Path $_.FullName -Pattern '^name:\s*(\S+)' | Select-Object -First 1
        if ($match) { $match.Matches[0].Groups[1].Value }
    }
}

# alias -> canonical source name (only for the small set of names people type
# from muscle memory; everything else must be the exact registry name)
$canonical = @{
    'fortigate' = 'fortigate_traffic'
    'suricata'  = 'suricata_eve_flow'
    'zeek'      = 'zeek_conn'
    'panos'     = 'panos_traffic_v10'
}

if ($List) {
    Write-Output 'Generator-supported sources (canonical name -> alias, if any):'
    $reverse = @{}
    foreach ($key in $canonical.Keys) { $reverse[$canonical[$key]] = $key }
    foreach ($name in (Get-UlpfSourceNames | Sort-Object)) {
        if ($reverse.ContainsKey($name)) {
            Write-Output ("  {0,-20} (alias: {1})" -f $name, $reverse[$name])
        }
        else {
            Write-Output ("  {0}" -f $name)
        }
    }
    exit 0
}

if (-not $Source) {
    throw '-Source is required (or pass -List to see every supported source).'
}
if ($canonical.ContainsKey($Source)) { $Source = $canonical[$Source] }

function Oct([int]$base, [int]$i) {
    # An IPv4 octet is 0-255. The old `$base + ($i % 200)` assumed every
    # caller picked a small $base (<=55); suricata_eve_alert's `Oct 200 $i`
    # didn't, so at high $i it emitted invalid octets like "203.0.113.399"
    # that the "ip" type coercion correctly rejected -> dead-lettered as
    # "invalid_ip". Compute the modulus from $base itself so the result is
    # ALWAYS in [$base, 255], for any $base a template passes in.
    $span = 256 - $base
    if ($span -le 0) { throw "Oct: base $base is already out of the 0-255 IPv4 octet range" }
    return $base + ($i % $span)
}

# Each template is a scriptblock: param($i) -> one well-formed line (string).
# Dictionary keys are the CANONICAL source definition names (see
# configs/sources/*.yaml `name:`), never aliases.
$templates = @{

    # RFC 3164 syslog + grok body. The 302013/302014 pattern needs the
    # inbound/outbound keyword AND the "iface:addr/port (mapped/port)"
    # structure TWICE (dst then src for outbound) -- direction is what tells
    # the parser which endpoint is the source.
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

    # RFC 5424 header + headerless PAN-OS TRAFFIC CSV, 10.x = 47 fields.
    'panos_traffic_v10' = {
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

    # Same envelope, but 11.x = 51 fields: one extra column inserted before
    # `ssl` (tunnel_inspection_rule) and three appended after `tcp-fin`.
    'panos_traffic_v11' = {
        param($i)
        $sid = 104512 + $i
        $sp  = 51234 + $i
        '<14>1 2026-09-01T12:00:03Z pa-fw1 - - - - ' +
        "1,2026/09/01 12:00:03,001801234567,TRAFFIC,end,2622,2026/09/01 12:00:00," +
        "192.0.2.$(Oct 15 $i),203.0.113.9,198.51.100.7,203.0.113.9,allow-web,,,,ssl," +
        "vsys1,trust,untrust,ethernet1/2,ethernet1/1,forward-all,,$sid,1,$sp,443," +
        "51235,443,0x400053,tcp,allow,5060,1240,3820,12,2026/09/01 11:59:48,12," +
        "web-advertisements,0,7000000123,0x0,192.0.2.0-192.0.2.255,United States,0,7,5," +
        "tcp-fin,0,1001,0"
    }

    # Suricata EVE JSON, event_type=flow -> OCSF 4001. No syslog framing.
    'suricata_eve_flow' = {
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

    # Suricata EVE JSON, event_type=alert -> OCSF 4001 with a signature.
    'suricata_eve_alert' = {
        param($i)
        $fid = 1234567890 + $i
        $sp  = 40333 + $i
        '{"timestamp":"2026-08-15T22:14:22.123456+0000","flow_id":' + $fid +
        ',"in_iface":"eth0","event_type":"alert","src_ip":"203.0.113.' + (Oct 200 $i) +
        '","src_port":' + $sp + ',"dest_ip":"192.0.2.30","dest_port":445,"proto":"TCP",' +
        '"pkt_src":"wire/pcap","alert":{"action":"blocked","gid":1,"signature_id":2100498,' +
        '"rev":7,"signature":"GPL ATTACK_RESPONSE id check returned root",' +
        '"category":"Potentially Bad Traffic","severity":2,' +
        '"metadata":{"created_at":["2010_09_23"],"updated_at":["2019_07_26"]}},' +
        '"flow":{"pkts_toserver":6,"pkts_toclient":4,"bytes_toserver":540,' +
        '"bytes_toclient":320,"start":"2026-08-15T22:14:20.001000+0000"},' +
        '"stream":0,"tx_id":0}'
    }

    # Zeek conn.log in JSON mode (literal dotted keys). No syslog framing.
    'zeek_conn' = {
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

    # Zeek dns.log in JSON mode.
    'zeek_dns' = {
        param($i)
        $sp = 40000 + $i
        '{"ts":1697062455.201000,"uid":"CpQdmn2iH8i0V0aMc' + ('{0:x4}' -f ($i % 65536)) +
        '","id.orig_h":"192.0.2.' + (Oct 15 $i) + '","id.orig_p":' + $sp +
        ',"id.resp_h":"203.0.113.53","id.resp_p":53,"proto":"udp","trans_id":' +
        (41230 + $i) + ',"rtt":0.051,"query":"example.com","qclass":1,' +
        '"qclass_name":"C_INTERNET","qtype":1,"qtype_name":"A","rcode":0,' +
        '"rcode_name":"NOERROR","AA":false,"TC":false,"RD":true,"RA":true,"Z":0,' +
        '"answers":["203.0.113.9","203.0.113.10"],"TTLs":[300.0,300.0],"rejected":false}'
    }

    # Zeek http.log in JSON mode.
    'zeek_http' = {
        param($i)
        $sp = 52000 + $i
        '{"ts":1697062455.310000,"uid":"CjhGs94Ci0V0aMcQ' + ('{0:x4}' -f ($i % 65536)) +
        '","id.orig_h":"192.0.2.' + (Oct 41 $i) + '","id.orig_p":' + $sp +
        ',"id.resp_h":"203.0.113.150","id.resp_p":80,"trans_depth":1,"method":"GET",' +
        '"host":"example.com","uri":"/index.html","referrer":"http://example.com/",' +
        '"version":"1.1","user_agent":"curl/8.0.1","request_body_len":0,' +
        '"response_body_len":1256,"status_code":200,"status_msg":"OK","tags":[],' +
        '"resp_fuids":["FEab12xyz"],"resp_mime_types":["text/html"]}'
    }

    # AWS VPC Flow Logs, default v2: positional, space-separated, 14 fields.
    'aws_vpc_flow' = {
        param($i)
        $sp = 51234 + $i
        $start = 1725278400 + $i
        $end   = 1725278460 + $i
        "2 123456789010 eni-0abc1234def567890 192.0.2.$(Oct 15 $i) 203.0.113.9 " +
        "$sp 443 6 14 1240 $start $end ACCEPT OK"
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

if (-not $templates.ContainsKey($Source)) {
    throw "-Source '$Source' is a known ULPF source definition, but this " +
        "generator has no template for it yet. Templated sources: " +
        "$(($templates.Keys | Sort-Object) -join ', ')"
}

$template = $templates[$Source]

function Send-Udp([System.Net.Sockets.UdpClient]$client, [string]$line) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($line)
    [void]$client.Send($bytes, $bytes.Length, $TargetHost, $Port)
}

function Send-TcpOctetCounted([System.Net.Sockets.NetworkStream]$stream, [string]$line) {
    # RFC 6587 octet-counting: "MSGLEN SP MSG", length measured in the
    # encoded BYTES ULPF's TCP listener will read, not characters -- matches
    # ulpf.ingest.syslog_tcp.read_frames exactly, and sidesteps the one
    # framing ambiguity RFC 6587 itself calls out (a message that happens to
    # start with digits+space) by never relying on newline framing at all.
    $body = [System.Text.Encoding]::UTF8.GetBytes($line)
    $prefix = [System.Text.Encoding]::ASCII.GetBytes("$($body.Length) ")
    $stream.Write($prefix, 0, $prefix.Length)
    $stream.Write($body, 0, $body.Length)
}

$udpClient = $null
$tcpClient = $null
$tcpStream = $null
if (-not $DryRun) {
    if ($Transport -eq 'udp') {
        $udpClient = New-Object System.Net.Sockets.UdpClient
    }
    else {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($TargetHost, $Port)
        $tcpStream = $tcpClient.GetStream()
    }
}

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$sent = 0
try {
    for ($i = 0; $i -lt $Count; $i++) {
        $line = & $template $i
        if ($DryRun) {
            Write-Output $line
        }
        elseif ($Transport -eq 'udp') {
            Send-Udp $udpClient $line
            Write-Verbose ("sent udp {0}:{1}  {2}" -f $TargetHost, $Port, $line)
        }
        else {
            Send-TcpOctetCounted $tcpStream $line
            Write-Verbose ("sent tcp {0}:{1}  {2}" -f $TargetHost, $Port, $line)
        }
        $sent++

        # Pace to at most RateEps events/sec: compare elapsed wall-clock time
        # against where the i'th send SHOULD land, rather than sleeping a
        # fixed interval every iteration -- that would drift by however long
        # the send itself took, compounding over a long run.
        if ($RateEps -gt 0 -and $i -lt ($Count - 1)) {
            $targetMs = ($i + 1) * (1000.0 / $RateEps)
            $waitMs = $targetMs - $stopwatch.Elapsed.TotalMilliseconds
            if ($waitMs -gt 0) { Start-Sleep -Milliseconds $waitMs }
        }
    }
    $stopwatch.Stop()

    if (-not $DryRun) {
        Write-Host ("sent {0} {1} line(s) to {2}:{3} over {4}" -f $Count, $Source, $TargetHost, $Port, $Transport)
    }
    if ($Report) {
        $elapsedSec = [Math]::Max($stopwatch.Elapsed.TotalSeconds, 0.0001)
        $rate = $sent / $elapsedSec
        Write-Host ("report: sent={0} elapsed={1:N3}s achieved_rate={2:N1} events/sec" -f $sent, $elapsedSec, $rate)
    }
}
finally {
    if ($udpClient) { $udpClient.Close() }
    if ($tcpStream) { $tcpStream.Close() }
    if ($tcpClient) { $tcpClient.Close() }
}
