#!/usr/bin/env python3
"""
Direct MMS Proxy (no SSLproxy, no iptables required).
Listens on one port, forwards to another port unmodified.
Useful for testing and development.

Usage: python3 mitm_mms_proxy.py --listen-port 102 --server-host 127.0.0.1 --server-port 103 [--parse]
"""

import socket
import sys
import argparse
import logging
import re
from enum import Enum
from threading import Thread

from iec61850_mms.mms.rt.report_decoder import decode_unconfirmed_report
from iec61850_mms.mms.rt.report_editor import mutate_unconfirmed_report_floats
from iec61850_mms.mms.rt.request_decoder import decode_write_request
from iec61850_mms.mms.rt.request_editor import mutate_write_request_floats

# Optional: Scapy parsing (non-destructive)
try:
    import scapy.all  # noqa: F401
    from iec61850_mms import bind_layers
    bind_layers()
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Setup logging - write to local file in current directory
log_handlers = [logging.StreamHandler()]
log_handlers.append(logging.FileHandler('mitm_mms_proxy.log'))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=log_handlers
)
logger = logging.getLogger(__name__)


class Direction(str, Enum):
    CLIENT_TO_SERVER = "client→server"
    SERVER_TO_CLIENT = "server→client"

    def __str__(self):
        return self.value


class MmsDirectProxy:
    """
    Simple direct proxy that forwards MMS traffic between client and server.
    
    Architecture:
      Client → Proxy (listen_port) → Server (server_host:server_port)
    """
    
    def __init__(
        self,
        listen_port,
        server_host,
        server_port,
        parse_mms=False,
        modify_report_floats=False,
        report_float_delta=21.0,
        report_float_percentage=None,
        report_float_path_regex=None,
        modify_write_floats=False,
        write_float_delta=0.0,
        write_float_percentage=None,
        write_float_path_regex=None,
    ):
        self.listen_port = listen_port
        self.server_host = server_host
        self.server_port = server_port
        self.parse_mms = parse_mms
        self.modify_report_floats = modify_report_floats
        self.report_float_delta = report_float_delta
        self.report_float_percentage = report_float_percentage
        self.report_float_path_regex = report_float_path_regex
        self.modify_write_floats = modify_write_floats
        self.write_float_delta = write_float_delta
        self.write_float_percentage = write_float_percentage
        self.write_float_path_regex = write_float_path_regex
        self.conn_id = 0

    def _direction_label(self, conn_id, direction):
        return f"[{conn_id}] {direction.value}"

    def rewrite_unconfirmed_floats(self, payload, direction, conn_id):
        if not self.modify_report_floats:
            return payload
        if direction != Direction.SERVER_TO_CLIENT:
            return payload

        label = self._direction_label(conn_id, direction)
        try:
            modified_payload, changed_count = mutate_unconfirmed_report_floats(
                payload,
                self.report_float_delta,
                self.report_float_path_regex,
                self.report_float_percentage,
            )
            if changed_count:
                op = (
                    f"{self.report_float_percentage:g}%"
                    if self.report_float_percentage is not None
                    else f"+{self.report_float_delta:g}"
                )
                if self.report_float_path_regex:
                    logger.info(
                        f"[{label}] Rewrote {changed_count} float value(s) with {op} "
                        f"for paths matching /{self.report_float_path_regex}/"
                    )
                else:
                    logger.info(
                        f"[{label}] Rewrote {changed_count} float value(s) with {op}"
                    )
            return modified_payload
        except Exception as exc:
            logger.debug(f"[{label}] Float rewrite failed: {exc}")
            return payload

    def rewrite_write_request_floats(self, payload, direction, conn_id):
        if not self.modify_write_floats:
            return payload
        if direction != Direction.CLIENT_TO_SERVER:
            return payload

        label = self._direction_label(conn_id, direction)
        try:
            modified_payload, changed_count = mutate_write_request_floats(
                payload,
                self.write_float_delta,
                self.write_float_path_regex,
                self.write_float_percentage,
            )
            if changed_count:
                op = (
                    f"{self.write_float_percentage:g}%"
                    if self.write_float_percentage is not None
                    else f"+{self.write_float_delta:g}"
                )
                if self.write_float_path_regex:
                    logger.info(
                        f"[{label}] Rewrote {changed_count} write-request float value(s) "
                        f"with {op} for paths matching /{self.write_float_path_regex}/"
                    )
                else:
                    logger.info(
                        f"[{label}] Rewrote {changed_count} write-request float value(s) "
                        f"with {op}"
                    )
            return modified_payload
        except Exception as exc:
            logger.debug(f"[{label}] Write-request float rewrite failed: {exc}")
            return payload

    def _format_decoded_value(self, value):
        value_type = value.get("type", "unknown")

        if value_type == "visible-string":
            return f"visible-string: {value.get('value', '')}"
        if value_type in ("unsigned", "integer", "boolean"):
            return f"{value_type}: {value.get('value')}"
        if value_type == "bit-string":
            return f"bit-string: {value.get('value', '')}"
        if value_type == "float":
            if "format_width" in value:
                return (
                    "float: "
                    f"format_width={value.get('format_width')} "
                    f"mantissa=0x{value.get('mantissa_hex', '')}"
                )
            return f"float: raw=0x{value.get('raw_hex', '')}"
        if value_type == "binary-time":
            if "milliseconds" in value:
                return f"binary-time: {value.get('milliseconds')} ms"
            return f"binary-time: raw=0x{value.get('raw_hex', '')}"
        if value_type == "utc-time":
            if "timestamp_utc" in value:
                return f"utc-time: {value.get('timestamp_utc')}"
            return f"utc-time: raw=0x{value.get('raw_hex', '')}"
        if value_type in ("structure", "array"):
            nested = value.get("values", [])
            return f"{value_type}: {len(nested)} item(s)"

        if "raw_hex" in value:
            return f"{value_type}: raw=0x{value.get('raw_hex', '')}"

        return str(value)

    def _log_decoded_value(self, direction, value, index_prefix):
        logger.info(f"[{direction}]   {index_prefix}{self._format_decoded_value(value)}")

        if value.get("type") in ("structure", "array"):
            for nested_idx, nested in enumerate(value.get("values", [])):
                self._log_decoded_value(direction, nested, f"{index_prefix}{nested_idx}.")

    def parse_unconfirmed_pdu(self, payload, direction_label):
        """Decode and log an UnconfirmedPDU report if present."""
        report = decode_unconfirmed_report(payload)
        if report is None:
            return False

        logger.info(f"\n{'='*80}")
        logger.info(f"[{direction_label}] *** PERIODIC REPORT (UnconfirmedPDU) DETECTED ***")
        logger.info(f"{'='*80}")
        logger.info(f"[{direction_label}] PERIODIC REPORT SUMMARY:")

        variable_names = report.get("variable_names", [])
        if variable_names:
            logger.info(f"[{direction_label}] Variable List Name: {variable_names}")
        else:
            logger.info(f"[{direction_label}] Variable List Name: []")

        values = report.get("values", [])
        logger.info(f"[{direction_label}] DATA VALUES:")
        if values:
            for idx, value in enumerate(values):
                self._log_decoded_value(direction_label, value, f"[{idx}] ")
        else:
            logger.info(f"[{direction_label}]   (empty - likely initialization)")

        logger.info(f"{'='*80}\n")
        return True

    def parse_write_request(self, payload, direction_label):
        """Decode and log a ConfirmedRequest/WriteRequest if present."""
        write_req = decode_write_request(payload)
        if write_req is None:
            return False

        logger.info(f"\n{'='*80}")
        logger.info(f"[{direction_label}] *** WRITE REQUEST (ConfirmedRequestPDU) DETECTED ***")
        logger.info(f"{'='*80}")

        invoke_id = write_req.get("invoke_id")
        if invoke_id is not None:
            logger.info(f"[{direction_label}] invokeID: {invoke_id}")

        var_refs = write_req.get("variable_references", [])
        logger.info(f"[{direction_label}] Variable References:")
        if var_refs:
            for idx, ref in enumerate(var_refs):
                logger.info(f"[{direction_label}]   [{idx}] {ref}")
        else:
            logger.info(f"[{direction_label}]   (not decoded)")

        values = write_req.get("values", [])
        logger.info(f"[{direction_label}] listOfData values:")
        if values:
            for idx, value in enumerate(values):
                self._log_decoded_value(direction_label, value, f"[{idx}] ")
        else:
            logger.info(f"[{direction_label}]   (empty)")

        logger.info(f"{'='*80}\n")
        return True

    def parse_and_log_mms(self, payload, direction, conn_id):
        """Optionally parse MMS content for logging (non-destructive)."""
        if not self.parse_mms or not payload:
            return

        label = self._direction_label(conn_id, direction)
        
        try:
            # Try to detect confirmed write requests.
            if self.parse_write_request(payload, label):
                return

            # Try to detect unconfirmedPDU first (periodic reports)
            if self.parse_unconfirmed_pdu(payload, label):
                return
            
            # Try to parse as general MMS
            from iec61850_mms.mms.packets import MMS
            pkt = MMS(payload)
            logger.info(f"[{label}] MMS: {pkt.summary()}")
        except Exception:
            # If parsing fails, just log the hex dump
            logger.debug(f"[{label}] Raw payload ({len(payload)} bytes): {payload[:64].hex()}...")
    
    def forward_data(self, src_sock, dst_sock, direction, conn_id):
        """Forward data between sockets."""
        try:
            while True:
                data = src_sock.recv(4096)
                if not data:
                    logger.info(f"[{conn_id}] Connection closed ({direction})")
                    break
                
                logger.debug(f"[{conn_id}] {direction.value}: {len(data)} bytes")
                out_data = self.rewrite_unconfirmed_floats(data, direction, conn_id)
                out_data = self.rewrite_write_request_floats(out_data, direction, conn_id)
                self.parse_and_log_mms(out_data, direction, conn_id)
                dst_sock.sendall(out_data)
        
        except Exception as e:
            logger.error(f"[{conn_id}] Error forwarding data ({direction}): {e}")
        finally:
            try:
                src_sock.close()
                dst_sock.close()
            except:
                pass
    
    def handle_client_connection(self, client_sock, client_addr):
        """Handle a new client connection."""
        self.conn_id += 1
        conn_id = self.conn_id
        
        logger.info(f"[{conn_id}] New client connection from {client_addr}")
        
        try:
            # Connect to real server
            logger.info(f"[{conn_id}] Connecting to server [{self.server_host}]:{self.server_port}")
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.connect((self.server_host, self.server_port))
            logger.info(f"[{conn_id}] Connected to server")
            
            # Set up bidirectional forwarding
            client_to_server = Thread(
                target=self.forward_data,
                args=(client_sock, server_sock, Direction.CLIENT_TO_SERVER, conn_id),
                daemon=True
            )
            server_to_client = Thread(
                target=self.forward_data,
                args=(server_sock, client_sock, Direction.SERVER_TO_CLIENT, conn_id),
                daemon=True
            )
            
            client_to_server.start()
            server_to_client.start()
            
            # Wait for both threads to finish
            client_to_server.join()
            server_to_client.join()
            
            logger.info(f"[{conn_id}] Connection closed")
        
        except Exception as e:
            logger.error(f"[{conn_id}] Error handling connection: {e}", exc_info=True)
        finally:
            try:
                client_sock.close()
            except:
                pass
    
    def start(self):
        """Start listening for client connections."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind(('0.0.0.0', self.listen_port))
        except OSError as e:
            if "Permission denied" in str(e) and self.listen_port < 1024:
                logger.error(f"Cannot bind to port {self.listen_port}. Ports < 1024 require root.")
                logger.error("Either run with sudo, or use a port >= 1024")
                sys.exit(1)
            raise
        
        server_socket.listen(5)
        
        logger.info(f"MMS Direct Proxy started")
        logger.info(f"  Listening on 0.0.0.0:{self.listen_port}")
        logger.info(f"  Forwarding to {self.server_host}:{self.server_port}")
        logger.info(f"  Scapy MMS parsing: {'enabled' if self.parse_mms else 'disabled'}")
        
        try:
            while True:
                client_sock, client_addr = server_socket.accept()
                logger.info(f"New connection from {client_addr[0]}:{client_addr[1]}")
                
                # Handle each connection in a separate thread
                handler = Thread(
                    target=self.handle_client_connection,
                    args=(client_sock, client_addr),
                    daemon=True
                )
                handler.start()
        
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            server_socket.close()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='MITM MMS Proxy - forwards traffic without SSLproxy or iptables'
    )
    parser.add_argument(
        '--listen-port', type=int, default=102,
        help='Port to listen on (default: 102, requires sudo for ports < 1024)'
    )
    parser.add_argument(
        '--server-host', default='127.0.0.1',
        help='MMS server host to forward to (default: 127.0.0.1)'
    )
    parser.add_argument(
        '--server-port', type=int, default=103,
        help='MMS server port to forward to (default: 103)'
    )
    parser.add_argument(
        '--parse', action='store_true',
        help='Enable MMS parsing for logging (report decoder + optional Scapy fallback)'
    )
    parser.add_argument(
        '--modify-report-floats', action='store_true',
        help='Add +21 to float values inside UnconfirmedPDU reports (server→client only)'
    )
    parser.add_argument(
        '--report-float-delta', type=float, default=21.0,
        help='Delta added to float values when --modify-report-floats is enabled (default: 21.0)'
    )
    parser.add_argument(
        '--report-float-percentage', type=float, default=None,
        help='Percentage applied to report float values relative to base value (e.g. 10 means +10%%)'
    )
    parser.add_argument(
        '--report-float-path-regex', default=None,
        help='Only modify periodic-report float values whose data attribute path matches this regex'
    )
    parser.add_argument(
        '--modify-write-floats', action='store_true',
        help='Modify float values inside WriteRequest listOfData (client→server only)'
    )
    parser.add_argument(
        '--write-float-delta', type=float, default=0.0,
        help='Delta added to WriteRequest float values when --modify-write-floats is enabled (default: 0.0)'
    )
    parser.add_argument(
        '--write-float-percentage', type=float, default=None,
        help='Percentage applied to write-request float values relative to base value (e.g. -5 means -5%%)'
    )
    parser.add_argument(
        '--write-float-path-regex', default=None,
        help='Only modify write-request float values whose data attribute path matches this regex'
    )
    
    args = parser.parse_args(argv)

    if args.report_float_path_regex is not None:
        try:
            re.compile(args.report_float_path_regex)
        except re.error as exc:
            parser.error(f"Invalid --report-float-path-regex: {exc}")

    if args.write_float_path_regex is not None:
        try:
            re.compile(args.write_float_path_regex)
        except re.error as exc:
            parser.error(f"Invalid --write-float-path-regex: {exc}")
    
    if not SCAPY_AVAILABLE and args.parse:
        logger.info("Scapy not available; using BER report decoder only")
    
    proxy = MmsDirectProxy(
        listen_port=args.listen_port,
        server_host=args.server_host,
        server_port=args.server_port,
        parse_mms=args.parse,
        modify_report_floats=args.modify_report_floats,
        report_float_delta=args.report_float_delta,
        report_float_percentage=args.report_float_percentage,
        report_float_path_regex=args.report_float_path_regex,
        modify_write_floats=args.modify_write_floats,
        write_float_delta=args.write_float_delta,
        write_float_percentage=args.write_float_percentage,
        write_float_path_regex=args.write_float_path_regex,
    )
    proxy.start()

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
