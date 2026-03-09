# CS2-ReconShell

A PowerShell RCON client for Counter-Strike 2 servers.

## Download

**[⬇ Download CS2-ReconShell.ps1](https://github.com/FakieNZ/CS2-ReconShell/releases/download/v1.0/CS2-ReconShell.ps1)**

## Setup

Unblock the file after downloading:
```powershell
Unblock-File -Path .\CS2-ReconShell.ps1
```

## Usage

```powershell
# Interactive shell
.\CS2-ReconShell.ps1

# With credentials
.\CS2-ReconShell.ps1 -ServerAddress YOUR_SERVER_IP:PORT -Password "yourpass"

# Single command
.\CS2-ReconShell.ps1 -ServerAddress YOUR_SERVER_IP:PORT -Password "yourpass" -Command "status"
```

## Features

- Interactive RCON shell with command history
- `host:port` address format support
- Custom alias mapping (shorthand → full RCON command)
- Idle keepalive to prevent disconnection
- Built-in commands: `help`, `aliases`, `history`, `clear`, `exit`

## Requirements

- PowerShell 5.1 or later
- CS2 server with RCON enabled
