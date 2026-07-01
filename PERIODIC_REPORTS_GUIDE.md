# Periodic Report Parsing

The proxy now detects and parses MMS periodic reports (UnconfirmedPDUs) in real-time.

## What are UnconfirmedPDUs?

Unsolicited MMS messages from devices/servers — typically periodic measurements and status updates (SCADA, monitoring, etc.).

## Usage

Run the proxy with `--parse` flag:

```bash
sudo python3 mms_direct_proxy.py \
  --listen-port 102 \
  --server-host 127.0.0.1 \
  --server-port 103 \
  --parse
```

When a report is detected, output shows:

```
[direction] *** PERIODIC REPORT (UnconfirmedPDU) DETECTED ***
[direction] PERIODIC REPORT SUMMARY:
[direction]   Variable List Name: [names...]
[direction]   DATA VALUES:
[direction]     [0] type: value
[direction]     [1] type: value
```

Monitor in real-time:

```bash
tail -f mms_direct_proxy.log | grep "PERIODIC REPORT"
```

---

## Advanced Usage

### Log Levels

The proxy supports different log verbosity levels:

- **INFO** (default): Connection events + periodic reports
- **DEBUG**: Detailed packet analysis + parse failures

To see debug logs:

```python
# Edit mms_direct_proxy.py, change line ~40:
logging.basicConfig(
    level=logging.DEBUG,  # Changed from INFO
    ...
)
```

### Persistent Logging

Logs are written to:
- Primary: `/tmp/mms_direct_proxy.log`
- Fallback: `./mms_direct_proxy.log`

### Custom Parsing

To extend the parsing for your specific needs, modify the `parse_unconfirmed_pdu()` method:

```python
def parse_unconfirmed_pdu(self, pdu_data, direction):
    # Add custom logic here
    # Extract specific fields
    # Call external handlers, etc.
```

---

## Packet Structure

### MMS UnconfirmedPDU Format

```
MMS_Unconfirmed_PDU
├── informationReport
    ├── variableAccessSpecification
    │   └── List of variable references
    └── listOfAccessResult
        └── List of data values
```

### Typical Periodic Report Contents

| Field | Contains | Example |
|-------|----------|---------|
| `variableAccessSpecification` | Variable identifiers/names | `["Temperature", "Pressure"]` |
| `listOfAccessResult` | Sensor readings/status values | `[23.5°C, 101.3 kPa]` |
| Timestamp | When the report was generated | Embedded in ACSE/COTP layers |

---

## Troubleshooting

### No Periodic Reports Detected

1. **Check proxy is running with `--parse` flag**
   ```bash
   ps aux | grep mms_direct_proxy
   # Should see: --parse
   ```

2. **Verify MMS server is actually sending periodic reports**
   ```bash
   tcpdump -i any -n port 102 -A
   # Look for COTP/MMS traffic
   ```

3. **Check log file exists and is being written**
   ```bash
   ls -la /tmp/mms_direct_proxy.log
   tail -20 /tmp/mms_direct_proxy.log
   ```

4. **Enable debug logging** (see Advanced Usage above)

### Parsing Failures

If you see "Failed to parse as UnconfirmedPDU" in debug logs:
- The packet might be incomplete or corrupted
- Check your network for packet fragmentation
- Verify MMS protocol compliance

### Permission Denied on Binding

```bash
# For ports < 1024, run with sudo:
sudo python3 mms_direct_proxy.py --listen-port 102 ...

# Or use a port >= 1024 and set up port forwarding:
sudo iptables -t nat -A PREROUTING -p tcp --dport 102 -j REDIRECT --to-port 1102
```

---

## Example Workflow

### Setup

```bash
# Terminal 1: Start MMS server
cd DER_SERVER
./exec/server

# Terminal 2: Start proxy with parsing
cd IEC61850-MMS-Scapy
python3 mms_direct_proxy.py --listen-port 102 --server-host 127.0.0.1 --server-port 103 --parse

# Terminal 3: Start client (connects via proxy)
cd DER_CLIENT
./exec/DER_Client

# Terminal 4: Monitor periodic reports
tail -f mms_direct_proxy.log | grep "PERIODIC REPORT"
```

### Expected Output

```
[server→client] *** PERIODIC REPORT (UnconfirmedPDU) DETECTED ***
[server→client] Information Report Summary:
  PDU Type: UnconfirmedPDU
  Content: MMS_Information_Report
  Variable Access Specification: ["/IED1/LN0/data"]
  Access Results:
    [0]: 42 (timestamp: 2025-12-10T14:30:45)
```

---

## Performance Notes

- **Non-blocking**: Periodic reports are parsed without blocking data forwarding
- **Memory**: Each report is parsed on-the-fly; no buffering
- **CPU**: Minimal overhead; parsing ~1000 reports/sec on typical hardware

---

## References

- ISO 68150-2: MMS Protocol
- IEC 61850: Power System Communication
- Wireshark MMS Dissector: `epan/dissectors/asn1/mms/mms.asn`

---

## Support

For issues or questions:
1. Check the log files
2. Enable debug logging
3. Capture a PCAP and inspect manually:
   ```bash
   tcpdump -i any port 102 -w capture.pcap
   # Then analyze in Wireshark
   ```
