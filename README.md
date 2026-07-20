# IEC61850-MMS-Scapy

This repository contains MMS parsing logic plus a practical MITM proxy executable:

- Command: `mitm-mms-proxy`
- Purpose: forward MMS traffic, parse key PDUs, and optionally rewrite float values in:
    - periodic reports (server -> client)
    - write requests (client -> server)

The initial codebase was derived from [iec61850-mms-scapy](https://github.com/rhelmke/iec61850_mms_scapy).

## Install

```bash
cd /home/roberta/MMS_Cli_Ser_Exp/IEC61850-MMS-Scapy
python3 -m pip install .
```

Recommended during active development:

```bash
python3 -m pip install -e .
```

Check CLI:

```bash
mitm-mms-proxy --help
```

## Quick Start

Run proxy on port 102 and forward to server on port 103:

```bash
sudo mitm-mms-proxy --listen-port 102 --server-port 103 --parse
```

Notes:

- Use `sudo` when listening on privileged ports (`<1024`).
- Logs are written to `./mitm_mms_proxy.log` and console.

## Common Commands

Parse only:

```bash
sudo mitm-mms-proxy \
    --parse \
    --listen-port 102 \
    --server-host 127.0.0.1 \
    --server-port 103
```

Modify periodic report floats by fixed delta:

```bash
sudo mitm-mms-proxy \
    --parse \
    --listen-port 102 \
    --server-port 103 \
    --modify-report-floats \
    --report-float-delta 50
```

Modify periodic report floats only for selected paths:

```bash
sudo mitm-mms-proxy \
    --parse \
    --listen-port 102 \
    --server-port 103 \
    --modify-report-floats \
    --report-float-delta 50 \
    --report-float-path-regex 'PdCMMXU1\$MX\$Tot(?:W|VAr)$'
```

Modify write-request floats by fixed delta:

```bash
sudo mitm-mms-proxy \
    --parse \
    --listen-port 102 \
    --server-port 103 \
    --modify-write-floats \
    --write-float-delta 50
```

Modify write-request floats only for selected paths:

```bash
sudo mitm-mms-proxy \
    --parse \
    --listen-port 102 \
    --server-port 103 \
    --modify-write-floats \
    --write-float-delta 50 \
    --write-float-path-regex '.*VArTgtSptPct'
```

Use percentage instead of delta (example: +10%):

```bash
sudo mitm-mms-proxy \
    --parse \
    --listen-port 102 \
    --server-port 103 \
    --modify-report-floats \
    --report-float-percentage 10
```

## What Gets Modified

- `--modify-report-floats`: only server -> client UnconfirmedPDU reports.
- `--modify-write-floats`: only client -> server ConfirmedRequest WriteRequest.
- Regex options target variable/path references and then apply mutation to corresponding float data entries.

## Troubleshooting

No rewrite logs:

1. Confirm flag is enabled (`--modify-report-floats` or `--modify-write-floats`).
2. Confirm direction is correct (reports are server -> client, writes are client -> server).
3. Confirm regex actually matches decoded references in logs.
4. Reinstall editable after code changes:

```bash
cd /home/roberta/MMS_Cli_Ser_Exp/IEC61850-MMS-Scapy
python3 -m pip install -e .
```

Shell quoting pitfalls for regex and IEC 61850 paths:

- Prefer single quotes in shell commands.
- `$` has special meaning in shell; unquoted or double-quoted patterns/paths may be altered.

Check recent activity:

```bash
tail -n 200 ./mitm_mms_proxy.log
```

Filter rewrite events:

```bash
grep -n "Rewrote" ./mitm_mms_proxy.log
```

## Optional: Scapy Layer Bindings

If you need to manually bind Scapy layers in custom scripts:

```python
import iec61850_mms
iec61850_mms.bind_layers()
```

## Protocol Coverage (Current)

```plain
MMS:
    - ConfirmedRequest (read, write, getnamelist)
    - ConfirmedResponse
    - InitiateRequest
    - InitiateResponse
    - UnconfirmedPDU

ACSE/ISO 8650-1:
    - AARQ
    - AARE

ISO 8823:
    - CP
    - CPA
    - CPC

ISO 8327-1:
    - User Data (DT)
    - Connect (CN)
    - Accept (AC)

COTP:
    - Data (DT)
    - Connection Requests (CR)
    - Connection Responses (CC)
```
