#Requires -Version 5.1
<#
.SYNOPSIS
    CS2 RCON Client - A PowerShell RCON client for Counter-Strike 2 servers.

.DESCRIPTION
    Connects to a CS2 (or any Source Engine) game server via RCON protocol.
    Supports interactive mode (REPL) and single-command execution.

.PARAMETER Host
    The server IP address or hostname.

.PARAMETER Port
    The RCON port (default: 27015).

.PARAMETER Password
    The RCON password.

.PARAMETER Command
    A single command to execute and exit (optional — omit for interactive mode).

.PARAMETER Timeout
    Connection/read timeout in milliseconds (default: 5000).

.EXAMPLE
    .\CS2-RCON-Client.ps1 -Host 192.168.1.100 -Password mypassword
    # Launches interactive RCON shell

.EXAMPLE
    .\CS2-RCON-Client.ps1 -Host 192.168.1.100 -Password mypassword -Command "status"
    # Runs a single command and exits

.EXAMPLE
    .\CS2-RCON-Client.ps1 -Host game.example.com -Port 27016 -Password secret -Command "mp_restartgame 1"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [Alias("h", "server")]
    [string]$ServerAddress,

    [Parameter(Mandatory = $false)]
    [Alias("p")]
    [int]$Port = 27015,

    [Parameter(Mandatory = $false)]
    [Alias("pass", "pw")]
    [string]$Password,

    [Parameter(Mandatory = $false)]
    [Alias("cmd", "c")]
    [string]$Command,

    [Parameter(Mandatory = $false)]
    [int]$Timeout = 5000
)

# ─── RCON Packet Types ────────────────────────────────────────────────────────
$SERVERDATA_AUTH            = 3
$SERVERDATA_AUTH_RESPONSE   = 2
$SERVERDATA_EXECCOMMAND     = 2
$SERVERDATA_RESPONSE_VALUE  = 0

# ─── Colour helpers ──────────────────────────────────────────────────────────
function Write-Color {
    param([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::White, [switch]$NoNewline)
    $prev = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $Color
    if ($NoNewline) { Write-Host $Text -NoNewline } else { Write-Host $Text }
    $Host.UI.RawUI.ForegroundColor = $prev
}

function Write-Banner {
$banner = @"

 ██████╗███████╗██████╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗██╗  ██╗███████╗██╗     ██╗
██╔════╝██╔════╝╚════██╗   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██║  ██║██╔════╝██║     ██║
██║     ███████╗ █████╔╝   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████╗███████║█████╗  ██║     ██║
██║     ╚════██║██╔═══╝    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║╚════██║██╔══██║██╔══╝  ██║     ██║
╚██████╗███████║███████╗   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║███████║██║  ██║███████╗███████╗███████╗
 ╚═════╝╚══════╝╚══════╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
"@
    Write-Color $banner -Color Cyan
    Write-Color "`n       CS2 RCON Client  |  Built by FakieNZ  |  PowerShell Edition  |  Type 'help' for commands`n" -Color DarkCyan
    Write-Color "       After connecting to CS2 Server, type 'help' for commands`n" -Color DarkCyan
}

# ─── RCON Packet Builder ─────────────────────────────────────────────────────
function Build-RconPacket {
    param([int]$Id, [int]$Type, [string]$Body)
    $bodyBytes  = [System.Text.Encoding]::UTF8.GetBytes($Body)
    # Packet: Size(4) + ID(4) + Type(4) + Body(N) + NullTerm(1) + Pad(1)
    $bodyLen    = $bodyBytes.Length
    $size       = 4 + 4 + $bodyLen + 2   # id + type + body + 2 nulls
    $packet     = New-Object byte[] (4 + $size)
    $writer     = New-Object System.IO.BinaryWriter([System.IO.MemoryStream]::new($packet))
    $writer.Write([int32]$size)
    $writer.Write([int32]$Id)
    $writer.Write([int32]$Type)
    $writer.Write($bodyBytes)
    $writer.Write([byte]0)  # body null terminator
    $writer.Write([byte]0)  # empty string null terminator
    $writer.Close()
    return $packet
}

# ─── RCON Packet Reader ──────────────────────────────────────────────────────
function Read-RconPacket {
    param([System.Net.Sockets.NetworkStream]$Stream, [int]$TimeoutMs)

    $Stream.ReadTimeout = $TimeoutMs

    # Read the 4-byte size field
    $sizeBytes = New-Object byte[] 4
    $read = 0
    while ($read -lt 4) {
        $n = $Stream.Read($sizeBytes, $read, 4 - $read)
        if ($n -eq 0) { throw "Connection closed by server." }
        $read += $n
    }
    $size = [System.BitConverter]::ToInt32($sizeBytes, 0)

    if ($size -lt 10 -or $size -gt 65536) {
        throw "Invalid packet size: $size"
    }

    # Read the rest of the packet
    $data = New-Object byte[] $size
    $read = 0
    while ($read -lt $size) {
        $n = $Stream.Read($data, $read, $size - $read)
        if ($n -eq 0) { throw "Connection closed by server." }
        $read += $n
    }

    $id   = [System.BitConverter]::ToInt32($data, 0)
    $type = [System.BitConverter]::ToInt32($data, 4)
    # Body is bytes 8..size-2 (strip two null terminators)
    $bodyLen = $size - 10
    $body = ""
    if ($bodyLen -gt 0) {
        $body = [System.Text.Encoding]::UTF8.GetString($data, 8, $bodyLen)
    }

    return @{ Id = $id; Type = $type; Body = $body }
}

# ─── Send command, collect full response ─────────────────────────────────────
function Send-RconCommand {
    param(
        [System.Net.Sockets.NetworkStream]$Stream,
        [int]$Id,
        [string]$Command,
        [int]$TimeoutMs
    )

    # Send the real command
    $pkt = Build-RconPacket -Id $Id -Type $SERVERDATA_EXECCOMMAND -Body $Command
    $Stream.Write($pkt, 0, $pkt.Length)

    # Send a sentinel EXECCOMMAND with a known ID so we know when the response ends.
    # CS2/Source engines mirror the sentinel back after the real response.
    $sentinelId = $Id + 1
    $sentinel   = Build-RconPacket -Id $sentinelId -Type $SERVERDATA_EXECCOMMAND -Body ""
    $Stream.Write($sentinel, 0, $sentinel.Length)

    $response = [System.Text.StringBuilder]::new()
    $deadline = [datetime]::UtcNow.AddMilliseconds($TimeoutMs)

    while ([datetime]::UtcNow -lt $deadline) {
        try {
            $pktIn = Read-RconPacket -Stream $Stream -TimeoutMs $TimeoutMs
        } catch [System.IO.IOException] {
            # Timeout on read — no more data
            break
        }

        if ($pktIn.Id -eq $sentinelId) {
            # Sentinel echoed back — response is complete
            break
        }

        if ($pktIn.Id -eq $Id -and $pktIn.Type -eq $SERVERDATA_RESPONSE_VALUE) {
            [void]$response.Append($pktIn.Body)
        }
    }

    return $response.ToString()
}

# ─── Authenticate ─────────────────────────────────────────────────────────────
function Connect-Rcon {
    param(
        [string]$ServerHost,
        [int]$ServerPort,
        [string]$RconPassword,
        [int]$TimeoutMs
    )

    Write-Color "  Connecting to " -Color Gray -NoNewline
    Write-Color "${ServerHost}:${ServerPort}" -Color Yellow -NoNewline
    Write-Color " ... " -Color Gray -NoNewline

    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.SendTimeout    = $TimeoutMs
        $tcp.ReceiveTimeout = $TimeoutMs
        $asyncResult = $tcp.BeginConnect($ServerHost, $ServerPort, $null, $null)
        $connected   = $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs)
        if (-not $connected) {
            $tcp.Close()
            throw "Connection timed out."
        }
        $tcp.EndConnect($asyncResult)
    } catch {
        Write-Color "FAILED" -Color Red
        Write-Color "  Error: $_" -Color DarkRed
        return $null
    }

    Write-Color "Connected" -Color Green

    $stream = $tcp.GetStream()

    # Send auth packet
    Write-Color "  Authenticating ... " -Color Gray -NoNewline
    $authPkt = Build-RconPacket -Id 1 -Type $SERVERDATA_AUTH -Body $RconPassword
    $stream.Write($authPkt, 0, $authPkt.Length)

    # CS2/Source: first response is RESPONSE_VALUE (empty), second is AUTH_RESPONSE
    try {
        $r1 = Read-RconPacket -Stream $stream -TimeoutMs $TimeoutMs
        # Some servers send an empty RESPONSE_VALUE first; consume it if needed
        if ($r1.Type -eq $SERVERDATA_AUTH_RESPONSE) {
            $authResponse = $r1
        } else {
            $authResponse = Read-RconPacket -Stream $stream -TimeoutMs $TimeoutMs
        }
    } catch {
        Write-Color "FAILED (no response)" -Color Red
        $tcp.Close()
        return $null
    }

    # An ID of -1 means authentication failed
    if ($authResponse.Id -eq -1) {
        Write-Color "FAILED (wrong password)" -Color Red
        $tcp.Close()
        return $null
    }

    Write-Color "Authenticated`n" -Color Green

    return @{ Tcp = $tcp; Stream = $stream }
}

# ─── Built-in help ───────────────────────────────────────────────────────────
function Show-Help {
    Write-Color "`n  Built-in commands:" -Color Cyan
    $cmds = @(
        @{ Cmd = "help";        Desc = "Show this help message" },
        @{ Cmd = "clear";       Desc = "Clear the screen" },
        @{ Cmd = "exit / quit"; Desc = "Disconnect and exit" },
        @{ Cmd = "history";     Desc = "Show command history" },
        @{ Cmd = "aliases";     Desc = "List all custom alias mappings" }
    )
    foreach ($c in $cmds) {
        Write-Color ("    {0,-20} {1}" -f $c.Cmd, $c.Desc) -Color White
    }
    Write-Color "`n  CS2 useful RCON commands:" -Color Cyan
    $cs2 = @(
        @{ Cmd = "status";                 Desc = "Show server status and connected players" },
        @{ Cmd = "sv_cheats 1";            Desc = "Enable cheats" },
        @{ Cmd = "mp_restartgame 1";       Desc = "Restart the game in 1 second" },
        @{ Cmd = "changelevel <map>";      Desc = "Change to map (e.g. de_dust2)" },
        @{ Cmd = "bot_add";                Desc = "Add a bot" },
        @{ Cmd = "bot_kick";               Desc = "Kick all bots" },
        @{ Cmd = "mp_warmup_end";          Desc = "End warmup immediately" },
        @{ Cmd = "say <message>";          Desc = "Broadcast chat message" },
        @{ Cmd = "kick <name>";            Desc = "Kick a player by name" },
        @{ Cmd = "banid 60 <steamid>";     Desc = "Ban a Steam ID for 60 min" },
        @{ Cmd = "listid";                 Desc = "List ban list" },
        @{ Cmd = "writeid";                Desc = "Save ban list to disk" },
        @{ Cmd = "exec <cfg>";             Desc = "Execute a config file" }
    )
    foreach ($c in $cs2) {
        Write-Color ("    {0,-30} {1}" -f $c.Cmd, $c.Desc) -Color DarkGray
    }
    Write-Host ""
}

# ─── Interactive REPL ─────────────────────────────────────────────────────────
function Start-RconShell {
    param($Connection, [string]$ServerHost, [int]$ServerPort, [int]$TimeoutMs, [hashtable]$Aliases = @{})

    $cmdHistory = [System.Collections.Generic.List[string]]::new()
    $cmdId = 10

    Write-Color "  Type 'help' for available commands. Type 'exit' to quit.`n" -Color DarkCyan

    while ($true) {
        Write-Color "  rcon" -Color DarkCyan -NoNewline
        Write-Color "@" -Color DarkGray -NoNewline
        Write-Color "${ServerHost}:${ServerPort}" -Color Yellow -NoNewline
        Write-Color " > " -Color DarkGray -NoNewline

        $input = Read-Host

        if ([string]::IsNullOrWhiteSpace($input)) { continue }

        $trimmed = $input.Trim()

        $builtIn = $true
        switch ($trimmed.ToLower()) {
            "exit"    { Write-Color "`n  Disconnecting...`n" -Color DarkCyan; return }
            "quit"    { Write-Color "`n  Disconnecting...`n" -Color DarkCyan; return }
            "help"    { Show-Help }
            "clear"   { Clear-Host; Write-Banner }
            "history" {
                if ($cmdHistory.Count -eq 0) {
                    Write-Color "  (no history yet)" -Color DarkGray
                } else {
                    $i = 1
                    foreach ($h in $cmdHistory) {
                        Write-Color ("  {0,3}  {1}" -f $i, $h) -Color DarkGray
                        $i++
                    }
                }
                Write-Host ""
            }
            "aliases" {
                if ($Aliases.Count -eq 0) {
                    Write-Color "  (no aliases defined)" -Color DarkGray
                } else {
                    Write-Color "`n  Aliases:" -Color Cyan
                    foreach ($key in ($Aliases.Keys | Sort-Object)) {
                        Write-Color ("    {0,-25} -> {1}" -f $key, $Aliases[$key]) -Color White
                    }
                }
                Write-Host ""
            }
            default   { $builtIn = $false }
        }
        if ($builtIn) { continue }

        $cmdHistory.Add($trimmed)

        # Resolve alias if one exists
        $resolved = $trimmed
        if ($Aliases.ContainsKey($trimmed.ToLower())) {
            $resolved = $Aliases[$trimmed.ToLower()]
            Write-Color "  ~ $resolved" -Color DarkGray
        }

        try {
            $response = Send-RconCommand -Stream $Connection.Stream -Id $cmdId `
                                         -Command $resolved -TimeoutMs $TimeoutMs
            $cmdId += 2

            if ([string]::IsNullOrEmpty($response)) {
                Write-Color "  (empty response)" -Color DarkGray
            } else {
                Write-Host ""
                foreach ($line in ($response -split "`n")) {
                    $line = $line.TrimEnd("`r")
                    if ($line -match "^\s*$") { continue }
                    Write-Color "  $line" -Color White
                }
                Write-Host ""
            }
        } catch {
            Write-Color "`n  Error sending command: $_" -Color Red
            Write-Color "  The connection may have been lost. Exiting.`n" -Color DarkRed
            return
        }
    }
}

# ─── Custom Aliases ──────────────────────────────────────────────────────────
# Add your own shorthand → RCON command mappings here
$aliases = @{
    "map airsoft"    = "host_workshop_map 3196303254"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

Write-Banner

# ── Prompt for missing parameters ────────────────────────────────────────────
if (-not $ServerAddress) {
    Write-Color "  Server (ip:port or ip): " -Color Gray -NoNewline
    $ServerAddress = Read-Host
    if ([string]::IsNullOrWhiteSpace($ServerAddress)) {
        Write-Color "  No host provided. Exiting." -Color Red
        exit 1
    }
}

# ── Parse host:port format ────────────────────────────────────────────────────
if ($ServerAddress -match '^(.+):(\d+)$') {
    $ServerAddress = $Matches[1]
    $Port          = [int]$Matches[2]
}

if (-not $Password) {
    Write-Color "  RCON Password : " -Color Gray -NoNewline
    # Use SecureString so password isn't echoed
    $securePw = Read-Host -AsSecureString
    $bstr     = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePw)
    $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    if ([string]::IsNullOrWhiteSpace($Password)) {
        Write-Color "  No password provided. Exiting." -Color Red
        exit 1
    }
}

Write-Host ""

# ── Connect & Authenticate ───────────────────────────────────────────────────
$conn = Connect-Rcon -ServerHost $ServerAddress -ServerPort $Port `
                     -RconPassword $Password -TimeoutMs $Timeout

if ($null -eq $conn) {
    exit 1
}

# ── Keepalive (background thread — works in both modes) ──────────────────────
$keepaliveStream   = $conn.Stream
$keepaliveInterval = 60  # seconds
$keepaliveJob = Start-ThreadJob -ScriptBlock {
    param($stream, $interval)
    while ($true) {
        Start-Sleep -Seconds $interval
        try {
            # Send an empty EXECCOMMAND — server echoes it back, keeping TCP alive
            $size  = [byte[]]::new(4); [System.BitConverter]::GetBytes([int32]14).CopyTo($size, 0)
            $id    = [byte[]]::new(4); [System.BitConverter]::GetBytes([int32]99).CopyTo($id, 0)
            $type  = [byte[]]::new(4); [System.BitConverter]::GetBytes([int32]2).CopyTo($type, 0)
            $nulls = [byte[]]@(0, 0)
            $pkt   = $size + $id + $type + $nulls
            $stream.Write($pkt, 0, $pkt.Length)
        } catch {
            break  # connection gone, stop quietly
        }
    }
} -ArgumentList $keepaliveStream, $keepaliveInterval

# ── Single-command mode ───────────────────────────────────────────────────────
if ($Command) {
    try {
        $response = Send-RconCommand -Stream $conn.Stream -Id 10 `
                                     -Command $Command -TimeoutMs $Timeout
        if ([string]::IsNullOrEmpty($response)) {
            Write-Color "(empty response)" -Color DarkGray
        } else {
            foreach ($line in ($response -split "`n")) {
                $line = $line.TrimEnd("`r")
                if ($line -match "^\s*$") { continue }
                Write-Host $line
            }
        }
    } catch {
        Write-Color "Error: $_" -Color Red
    } finally {
        $conn.Tcp.Close()
    }
    exit 0
}

# ── Interactive mode ──────────────────────────────────────────────────────────
Start-RconShell -Connection $conn -ServerHost $ServerAddress -ServerPort $Port -TimeoutMs $Timeout -Aliases $aliases

Stop-Job $keepaliveJob -ErrorAction SilentlyContinue
Remove-Job $keepaliveJob -ErrorAction SilentlyContinue
$conn.Tcp.Close()
Write-Color "  Goodbye!`n" -Color DarkCyan
