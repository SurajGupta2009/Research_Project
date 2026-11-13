# Research findings: NetHunter, ANDRAX, and the Redmi Pad SE 4G

**Prepared:** 2026-11-12

**Scope:** Fact-check of the 17-page “Kali NetHunter vs ANDRAX Comparison” PDF, plus device-specific analysis of the user’s rooted Redmi Pad SE 4G internal Wi-Fi driver.

**Important:** The device findings below are based on the screenshots and command output supplied by the user. They are not a claim that the internal Wi-Fi has been successfully used for monitor-mode capture or injection.

## Executive summary

- The PDF gets some general distinctions right, but repeatedly turns generic platform facts into unsupported claims about the Redmi Pad SE 4G. Its categorical claims about the tablet’s internal Wi-Fi and Wi-Fi firmware verification are not established.
- The tablet is model **24076RP19I**, running Android 14 / HyperOS **1.0.1.0.UHYINXM**, kernel **5.10.198-android12-9+**, on MediaTek Helio G85. It is rooted and has NetHunter installed.
- Its current MediaTek `wlan_drv_gen4m` driver advertises managed, AP, P2P, and IBSS modes through `iw`; it does **not** advertise standard `nl80211` monitor mode.
- The uploaded driver binary contains `priv_driver_sniffer`, `wlanoidSetIcsSniffer`, the `SNIFFER` string, and a private ICS path. Static analysis links the handler state bytes to a conditional RX path that prepends a custom 12-byte header and calls the external ICS writer with header plus RX-buffer bytes. The companion module implements a 64 KiB byte ring; the tablet confirms the writer provider and `/dev/fw_log_ics` node are loaded/present, but neither actual writer invocation nor a userspace capture was observed.
- Static analysis of the uploaded `/system_ext/bin/connsyslogger` confirms it is the vendor userspace logger for multiple firmware-log ports, including `/dev/fw_log_ics`. `ReorganizePort` intersects the property-supported ports with the non-default customization list. Here `bt,wifi,gps,mcu` intersected with `wifi,ics` yields only `WIFI`, so the code-derived selection excludes ICS. The running UID-2000 process also could not pass DAC on `/dev/fw_log_ics` (`0600 root:root`); no ICS descriptor was observed. The logger's generic code reads selected streams and writes logs under `/data/connsyslog`, but that does not establish full raw 802.11 capture.
- The vendor policy rules name `connsyslogger_31_0`, while the process reports `u:r:connsyslogger:s0`; their alias/compatibility relationship is unverified. This does not affect the observed DAC denial on the ICS node.
- The `mtklog-config.prop` setting `com.mediatek.log.connsysfw.enabled=false` belongs to the separate MediaTek logger configuration and does not override the `connsyslogger` service state. The ICS stream format and full-frame status remain unknown; standard monitor/Radiotap capture and injection are unproven. The private ten-field sniffer parser has overlapping destinations, so do not guess or invoke its command. Bluetooth is ON and its HAL uses `/dev/stpbt`, but Bluetooth RF sniffing remains unproven.

## Device identification and supplied diagnostics

### About-tablet screenshots

- Model: `24076RP19I` (India variant of the Redmi Pad SE 8.7 4G / `spark` family).
- OS: HyperOS `1.0.1.0.UHYINXM`; Android 14 (`UP1A.231005.007`).
- Android security update shown: 2024-06-01.
- SoC: MediaTek Helio G85; physical RAM shown as 4 GB, with 2 GB memory extension also shown.
- Kernel: `5.10.198-android12-9-00085-g226a9632f13d-ab11136126`.

Xiaomi’s public kernel repository lists `spark-s-oss` and `spark-w-oss` for the Redmi Pad SE 4G family. Public kernel source is not itself a complete, tested NetHunter kernel or proof of Wi-Fi monitor/injection support: [Xiaomi_Kernel_OpenSource](https://github.com/MiCode/Xiaomi_Kernel_OpenSource).

### `iw` and module output

`iw dev` reports one wiphy (`phy#0`) and interfaces:

- `wlan0`: managed, connected to the user’s AP.
- `wlan1`: managed, down.
- `ap0`: AP.
- `p2p0`: P2P client.

`iw list` reports interface modes `IBSS`, `managed`, `AP`, `P2P-client`, and `P2P-GO`; **monitor mode is absent**. The supported commands list includes generic nl80211 operations, but those entries do not establish raw 802.11 monitor capture or arbitrary injection.

The user’s sysfs and module output identifies:

- `/sys/class/net/wlan0/device -> ../../../18000000.wifi`.
- Driver binding: `/sys/bus/platform/drivers/wlan`.
- Loaded modules include `wlan_drv_gen4m`, `wmt_chrdev_wifi`, and `wmt_drv`.
- The `fmradio_drv_mt6631` module name does not, by itself, identify the Wi-Fi silicon.

The vendor module at `/vendor/lib/modules/wlan_drv_gen4m.ko` has SHA-256 `d6c0d8cbba0e1a9c23e116eea595a59c09318e0c8a7302124db3dc2ae3ea6e17` and `vermagic` `5.10.198-android12-9+ SMP preempt mod_unload modversions aarch64`, matching the kernel family shown in the screenshot.

### Sniffer-path analysis

Read-only `strings` and ELF-symbol inspection found:

- `priv_driver_sniffer` (local function, 732 bytes).
- `wlanoidSetIcsSniffer` (global function, 580 bytes).
- `priv_driver_cmds`, `priv_cmd_handlers`, and the `SNIFFER` string.
- Error/log strings including `SNIFFER CMD: Number of PARAMETERS is WRONG`, `ICS STOP`, `ICS Action ERROR`, and `wlanoidSetIcsSniffer failed`.
- `wlanSetPromiscuousMode` and `nicRxEnablePromiscuousMode` symbols also exist, but their presence does not show that they implement raw monitor mode.

The supplied disassembly of `priv_driver_sniffer` shows it looks for `=` and calls `sscanf` using this format:

```text
%d-%d-%d-%d-%x-%d-%d-%d-%d-%d
```

It requires ten parsed values, then passes an 80-byte structure through the driver OID path. The relocation table confirms a handler-table entry for `wlanoidSetIcsSniffer`. The supplied disassembly of that setter validates the structure length and submits a vendor firmware command with ID `0x93`.

Thus the likely command *shape* is `SNIFFER=<ten hyphen-separated values>`; the fifth is hexadecimal. **This is only the parser format, not a usable command. The meanings, safe values, required state, and capture/output mechanism remain unknown.** In particular, there is no evidence yet that `SNIFFER` creates `radiotap0` or exposes full 802.11 frames to `tcpdump`.

### Follow-up static analysis of uploaded driver and firmware

The user uploaded `wlan_drv_gen4m.ko`, `WIFI_RAM_CODE_soc1_0_1a_1.bin`, and `soc1_0_ram_wifi_1a_1_hdr.bin` for read-only analysis.

- The uploaded driver is an ELF64 little-endian AArch64 relocatable kernel module. Its SHA-256 is `d6c0d8cbba0e1a9c23e116eea595a59c09318e0c8a7302124db3dc2ae3ea6e17`, matching the SHA-256 previously reported for `/vendor/lib/modules/wlan_drv_gen4m.ko`. On that basis, the analyzed module is byte-for-byte matched to the tablet’s reported installed module.
- The main firmware SHA-256 is `e9d8b606043910764568af610f09dccaf5e24abfc3ec85651cb472f4d5295030`; the header SHA-256 is `a5c670e81bc76a12271a8ce56c65d6b7f353462c91c42adbdb9229994304e589`. Both match the values previously reported from the tablet.
- The parser’s ten `sscanf` destination pointers are at offsets `0, 1, 2, 3, 4, 6, 8, 10, 12, 14` within the same local request buffer. The format uses unmodified `%d` and `%x` conversions; standard kernel `sscanf` conversions write `int` values, so these destinations overlap. This may rely on values fitting into packed lower bytes/halfwords, but the disassembly does not reveal field names or safe ranges. Treat the parsed bytes and any guessed command line as untrusted; this is not a safe command recipe.
- `wlanoidSetIcsSniffer` checks for an input of at least `0x50` (80) bytes, then builds a zero-initialized `0x54` (84) byte firmware buffer. It remaps the first input bytes into positions 1 and 4–6, copies input bytes 4–15 into firmware-buffer positions 8–19, and submits command ID `0x93` as a set operation without requesting a firmware response. This confirms the private command path, not the meaning of command `0x93` or the ten parameters.
- The handler uses input byte 1 and the 16-bit value at input offset 4 to update two bytes in adapter state at offset `0x1058b0`. The RX function (`nicRxProcessRFBs`, ELF `.text` offset `0x5bfcc`) checks those same two bytes. If either is nonzero and the allocation succeeds, it reads a 16-bit length from the RX-side object, allocates an `skb`, and constructs a 12-byte prefix followed by that many bytes copied from the RX-side data pointer. The prefix is: 32-bit magic `0x44e98caf` (little-endian bytes `af 8c e9 44`), four zero bytes, 16-bit header length `12`, and 16-bit copied-data length (little-endian). It calls `wifi_ics_fwlog_write` with total length `12 + copied-data length`; it compares the return value with that requested total and then frees the skb. This is evidence for a custom framed RX-data logging path, not proof that the copied bytes are complete 802.11 frames, include FCS, or contain channel/rate/timestamp metadata. The RFB data layout and the private header’s wider schema are not established.
- Static analysis of the uploaded `wmt_chrdev_wifi.ko` shows `wifi_ics_fwlog_write` copying supplied bytes into a 64 KiB circular buffer and waking readers. Its `fw_log_ics` character-device implementation has read, poll, and ioctl handlers. Reads copy whatever bytes are currently available, bounded by the caller's requested size and ring wrap; no record-boundary API is evident. The reader therefore exposes a byte stream: one RX write may be split across reads or coalesced with adjacent writes. The writer computes available ring space and can return fewer bytes than requested; the RX caller notices a short result but does not retry the remainder. Thus a record may be truncated at the ring boundary when space is insufficient. No record-boundary API or overrun recovery protocol is evident, so a consumer must parse framing and handle loss rather than assume each `read()` returns one complete record. The module registers `fw_log_ics`, later confirmed at runtime as `/dev/fw_log_ics`. The ioctl dispatcher recognizes `0x4004fc00` for ICS log on/off and `0x4004fc01` for ICS log level, forwarding a 32-bit argument to a registered callback; accepted values and side effects are not established, so do not invoke these undocumented controls.
- This establishes the **static** producer-to-ring-to-character-device design. Runtime evidence only confirms that the WLAN/companion modules and writer symbol are loaded and the node exists. It does not show that the RX condition was enabled, the writer was called, bytes reached the ring, or any reader consumed them. The later logger analysis predicts ICS is not selected by the current property/customization intersection, and no ICS FD was observed. Treat the stream as custom ICS bytes; do not call it pcap/Radiotap or a working capture.
- The main firmware contains `Sniffer Mode Band%d %d` at file offset `0x85c50`, `RXM: Enable promiscuous mode` at `0x85cac`, and `RXM: Disable promiscuous mode` at `0x85ccc`, adjacent to a source-path string for `.../mlm/rxm_cmm.c`. These strings support the presence of firmware-side sniffer/promiscuous code; they do not decode command `0x93`, prove monitor-mode frame delivery, or establish injection.

### Device-side follow-up from `session2.log`

The new read-only log confirms the exact device fingerprint `Redmi/spark_in/spark:14/UP1A.231005.007/V816.0.1.0.UHYINXM:user/release-keys` and re-reports the same three Wi-Fi driver/firmware hashes as above.

- `/proc/kallsyms` reports `wifi_ics_fwlog_write` as a global text symbol provided by `[wmt_chrdev_wifi]`; `/proc/modules` shows `wmt_chrdev_wifi` loaded. The uploaded `wmt_chrdev_wifi.ko` hash is `d703e0f8dfdfe9d96a54c7d783b181742a5b605118c8fac2392f9c12987e725d`. The runtime symbol confirms a loaded provider, although no tablet-side SHA-256 for this companion module was supplied.
- The `wmt_chrdev_wifi.ko` binary implements the writer and the reader side: a 64 KiB circular buffer, wakeups, read/poll operations that expose buffered data to userspace, and ICS logging on/off/level ioctl strings. Session 3 confirms `/dev/fw_log_ics` exists as character device 472:0, mode `0600`, owner/group `root:root`, SELinux type `fw_log_ics_device`. Its DAC mode allows root access but denies ordinary access to the `wifi` and `bluetooth` groups; SELinux may impose additional restrictions. No read was attempted. At that point no reader had been identified; later analysis of `connsyslogger` found an intended port reader, though its process cannot pass the node’s current DAC permissions. The record schema remains unknown.
- The uploaded Bluetooth artifacts have SHA-256 values `0d1303ebdc4e19124a4fc0398fe1977793eb28929aa69d4e9e86404d93d4f5e9` (`bt_drv_connac1x.ko`), `7696bb23a111a4632acdcf700ff9160d8eeaac8b07239719df968c2a8bf966b7` (`BT_FW.cfg`), and `fc70418e66cc7ba6864ab1ac14a970c3c36b64a3152ba5766c947fa427366fc5` (`soc1_0_ram_bt_1a_1_hdr.bin`). No device-side hashes were supplied for these, so exact binary identity is not independently confirmed.
- Static inspection of `bt_drv_connac1x.ko` confirms an AArch64 module with kernel `5.10.198-android12-9+` vermagic and a dependency on `wmt_drv`, consistent with the loaded stack. Its symbols include HCI send/read/write and firmware-log interfaces (`send_hci_frame`, `BT_read`, `BT_write`, `fw_log_bt_*`); these show a Bluetooth transport/diagnostic path, not over-the-air packet sniffing. `BT_FW.cfg` contains coexistence/antenna settings and commented vendor-command examples. The firmware header identifies a MediaTek Connac build family, but these artifacts do not establish a precise controller model or RF-monitor capability.
- At the time of the snapshot, `dumpsys bluetooth_manager` reports Bluetooth OFF and the Bluetooth service disconnected; `/sys/class/bluetooth` is empty. The dump also records two historical Bluetooth service crashes. This is not evidence that Bluetooth hardware is absent, but it means the log does not establish active HCI capabilities or over-the-air capture.
- The captured kernel messages show routine Wi-Fi link/statistics commands and firmware-log reads; they do not show the private sniffer command being issued or prove an ICS capture session.

### Device-side follow-up from `session3.log`

This later read-only snapshot is from the same model, build fingerprint, and kernel. All seven hashes collected from `/vendor` match byte-for-byte the corresponding uploaded artifacts, including both radio modules and all listed Wi-Fi/Bluetooth firmware/configuration files.

- The live `iw dev` output shows `wlan0` and `wlan1` in managed mode, `ap0` in AP mode, and `p2p0` as P2P-client. `iw list` advertises IBSS, managed, AP, and P2P modes, but **not monitor mode**. It lists 2.4 GHz and 5 GHz channels. The device supports nl80211 frame operations in advertised modes, but this is not evidence of arbitrary raw-frame injection.
- `/dev/fw_log_ics` is present as character device 472:0, mode `0600`, owner/group `root:root`, SELinux label `fw_log_ics_device`. Its DAC mode allows root access but denies ordinary access to the `wifi` or `bluetooth` groups; SELinux may impose additional restrictions. No one opened/read it and no ICS ioctl or capture mode was invoked. `/dev/fw_log_wifi` (group `wifi`), `/dev/fw_log_bt` and `/dev/stpbt` (group `bluetooth`) also exist. These prove vendor diagnostic/transport endpoints exist, not that their data are captures or that they are safe to read without understanding their contracts.
- Android's Bluetooth manager now reports Bluetooth enabled and `ON`, with normal profile services active and one bonded BR/EDR device. This differs from the earlier OFF/disconnected snapshot and confirms the Android control plane can start Bluetooth. However, `/sys/class/bluetooth` is empty, no `hci0` node is present, and `btmgmt`, `hciconfig`, and `hcitool` were unavailable. Therefore the snapshot does not independently establish a usable raw HCI interface or RF-monitor/sniffer feature. The log's Bluetooth address, bonded-device address/name, Wi-Fi SSID/MACs, and IP addresses are intentionally omitted here because they are identifying information.
- Searching the listed vendor/system binary and config directories for `fw_log_ics`, `fw_log_bt`, or `stpbt` found literal matches in the `wmt_chrdev_wifi.ko` and policy/label/config files (`precompiled_sepolicy`, `vendor_file_contexts`, `vendor_sepolicy.cil`, and `ueventd.rc`). It did not identify a literal-string userspace executable or library reader in the searched locations. This is not exhaustive for apps or data partitions.
- Kernel messages still show routine Wi-Fi operation and firmware-log reads, with no evidence of an ICS capture session or the private sniffer command being issued.

### Device-side follow-up from `session4.log`

- The `ueventd.rc` excerpts set `/dev/stpbt` and `/dev/fw_log_bt` to mode `0660` with group `bluetooth`, and `/dev/fw_log_wifi` to `0660` with group `wifi`. No explicit `/dev/fw_log_ics` rule appears in the shown excerpts, consistent with its observed `0600 root:root` node. `vendor_file_contexts` assigns it the `fw_log_ics_device` SELinux type.
- The vendor SELinux policy contains allow rules for a domain named `connsyslogger_31_0` to use the `fw_log_ics_device`, `fw_log_wifi_device`, and `fw_log_bt_device` character devices. A later process check found `/system_ext/bin/connsyslogger` running as UID 2000 / GID 1007, with SELinux context `u:r:connsyslogger:s0` and no effective capabilities. That runtime type differs textually from `connsyslogger_31_0`; whether they are aliases or otherwise related has not been verified, so the policy rule cannot yet be attributed to this process. More decisively, `/dev/fw_log_ics` is `0600 root:root`: this unprivileged process is denied by DAC regardless of an SELinux allow rule. It had no ICS file descriptor. No privileged helper or permission change was observed.
- A current `/proc/*/fd` scan found process `bluetooth@1.1-s` holding `/dev/stpbt` open. Together with Bluetooth ON in session 3, this confirms the Android Bluetooth HAL is using the vendor STP transport endpoint. No process in that scan held `/dev/fw_log_ics` or `/dev/fw_log_bt` open, so no active firmware-log reader was observed at that moment.
- The process check identified init definitions at `/system_ext/etc/init/consyslogger.rc` and `/system_ext/etc/init/hw/meta_init.system.rc`, plus the daemon binary `/system_ext/bin/connsyslogger`. Initial broad literal searches did not surface a reader; static analysis of this exact executable later confirmed its embedded firmware-log device paths and read/log pipeline.

### Static analysis of the uploaded logger files

The user uploaded `consyslogger.rc`, `meta_init.system.rc`, and `/system_ext/bin/connsyslogger`.

- The daemon is an AArch64 ELF64 position-independent executable (148,840 bytes); its uploaded SHA-256 is `151589cae06ced2b28a7c8b3577c90dae55a35403c1b4cd716f9a5129dd737f6`. The binary contains `/dev/fw_log_ics` alongside `/dev/fw_log_wifi`, `/dev/fw_log_bt`, `/dev/fw_log_gps`, `/dev/fw_log_wmt`, `/dev/fw_log_wifimcu`, and `/dev/fw_log_btmcu`.
- Its embedded symbols and disassembly show a generic firmware-log port manager: it selects supported ports using `ro.vendor.connsys.dedicated.log.port`, opens selected device nodes read/write and nonblocking, uses the firmware-log on/off and log-level ioctls, reads from ports, and writes collected logs under `/data/connsyslog`. This confirms `connsyslogger` is the intended userspace logging consumer for the ICS node when that port is enabled/configured; it is not evidence that the log contents are full raw 802.11 captures.
- The service definition in `consyslogger.rc` is configured for user `shell`, with supplementary groups including `wifi` and `bluetooth`. It creates `/data/connsyslog` at `post-fs-data`; the service is marked `disabled` there and has a property-gated start rule requiring `persist.vendor.connsysfw.enable=true`, `vendor.connsys.driver.ready=yes`, and an empty `vendor.connsysfw.exit`. A second service stanza in `meta_init.system.rc` names the same binary but omits `disabled`, so effective init ordering/configuration should not be inferred from one file alone. The supplied runtime snapshot confirms the process was running.
- The runtime values show the three service property conditions satisfied and `init.svc.connsyslogger=running`. Its dedicated-port property is `bt,wifi,gps,mcu`, with no literal `ics` token. The binary's port descriptor table maps the seven labels to device paths in order: `WIFI`→`/dev/fw_log_wifi`, `BT`→`/dev/fw_log_bt`, `GPS`→`/dev/fw_log_gps`, `MCU`→`/dev/fw_log_wmt`, `WIFIMCU`→`/dev/fw_log_wifimcu`, `BTMCU`→`/dev/fw_log_btmcu`, `ICS`→`/dev/fw_log_ics`. Thus the runtime property names four regular port categories and does not list the separate ICS port.
- Separately, the uploaded `/data/connsyslog/customize_data.prop` (128 bytes, matching the device-side `ls -lZ` size) contains `bootup_auto_start=true`, `connsys_module_support=wifi,ics`, `file_counts=3`, and `single_file_size=30`; NUL padding follows the text in the fixed-size file. The customization explicitly requests Wi-Fi and ICS; this is not merely the binary's compiled default. In `ReorganizePort` (ELF VA `0x1a9f0`), the daemon reads `CustomizeParser::getCustomizeModule` and `getCustomizePorts`, iterates seven candidate port IDs, checks each against the property-derived supported-port set, and in the non-default customization branch also searches the customization string for that candidate. With the supplied values, the only intersection is `WIFI`: the dedicated property omits the separate `ICS` label, so the code-derived selected-port list should contain `/dev/fw_log_wifi`, not `/dev/fw_log_ics`. This is a static prediction from the supplied binary and configuration, not an observed logger trace.
- The same Drive upload includes `/system_ext/etc/mtklog-config.prop` (853 bytes) and `/vendor/etc/init/mtklog.rc` (603 bytes); device-side `ls -lZ` confirms both paths exist, labeled `system_file` and `vendor_configs_file` respectively. The property file sets `com.mediatek.log.connsysfw.enabled=false`, `com.mediatek.log.bthost.enabled=false`, and `com.mediatek.log.gpshost.enabled=false`; it separately sets `com.mediatek.log.wifisa.enabled=true` with three 30-MB files under `/data/log_wifi_temp/`. This is the MediaTek logger configuration and should not be conflated with the separate `connsyslogger` service, whose runtime state is `running`. `mtklog.rc` only shows boot-complete printk/dynamic-debug writes and UART-console property handling; it does not grant ICS-node access or establish capture.
- The uploaded customize file's device metadata is `-rw-rw---- shell:log`, SELinux type `consyslog_data_file`; the tablet-side check was run from a root prompt but reported the file unreadable. The files' content is now available from Drive, but why that device shell could list the files and not pass its `-r` test remains unexplained. No content was obtained from `/data/connsyslog/connsyslog_config`; the binary references `customize_data.prop` instead.
- This logger may open the separate `fw_log_wifi` and `fw_log_bt` nodes under its configured groups and their `0660` permissions. It cannot open `/dev/fw_log_ics` in its observed current state: that node is `0600 root:root`, while the daemon is UID 2000 with no effective capabilities. No ICS file descriptor was found. No permission changes or privileged helper were shown.

**Updated assessment:** `connsyslogger` is the intended userspace log reader and is running with its service properties satisfied. The binary maps the seven port labels to device paths, and `ReorganizePort` filters candidates against both the property list and the non-default customize list. With `bt,wifi,gps,mcu` intersected with `wifi,ics`, static analysis predicts that only `WIFI` is selected; ICS is excluded before any attempt to open `/dev/fw_log_ics`. The process also could not open that node under the observed `0600 root:root` DAC permissions, and no ICS descriptor was seen. Therefore there is no evidence of a working logger-to-file ICS capture on this snapshot. The policy's version-suffixed `connsyslogger_31_0` type still needs reconciliation with runtime type `connsyslogger`, but it does not alter the selection result or DAC barrier. The ICS record schema and whether it contains full frames remain unknown; standard monitor mode is absent from current `iw` capabilities, and raw capture/injection remain unproven. Bluetooth is not merely switched on: its HAL holds `/dev/stpbt` open, but that does not establish RF-monitor/sniffer support. Neither Wi-Fi injection nor Bluetooth over-the-air sniffing has been demonstrated.

The earlier public Realme Narzo 30A guide describes a different device/kernel and a different `MONITOR` command. It is not a verified procedure for this Xiaomi: [Realme Gen4m reverse-engineering guide](https://github.com/Minecraftcon/realme-reverse-engineering/blob/main/RMX3171/wifi/MEDIATEK_WIFI_MONITOR_REVERSE_ENGINEERING.md).

## Fact-check of the PDF answers

The source PDF was assessed answer by answer. The following twelve entries cover its separate response topics, not just broad themes.

### 1. Tailored NetHunter-versus-ANDRAX comparison

**Verdict: Partly accurate; device-specific conclusions are unsupported.** Xiaomi’s published specifications support the Helio G85 and the relevant RAM option. They do not establish ANDRAX compatibility, performance, or Wi-Fi capabilities. NetHunter Rootless, Lite, and full/device-specific NetHunter have different requirements; full hardware features rely on a suitable device-specific kernel. The PDF’s claims that ANDRAX has a particular static/Bionic build, crashes on this HyperOS build, or performs reliably in a given RAM configuration were not demonstrated. Android’s restriction on executing files from an app’s writable private directory is not a universal block on all native binaries. Sources: [Xiaomi specs](https://www.mi.com/in/product/redmi-pad-se-4g/specs/), [NetHunter documentation](https://www.kali.org/docs/nethunter/), [Android 10 behavior changes](https://developer.android.com/about/versions/10/behavior-changes-10).

### 2. Custom kernel, flashing, and external Wi-Fi instructions

**Verdict: Directionally reasonable but not a verified recipe for this device.** A kernel may add drivers and device features, but a patch alone cannot make unsupported hardware/firmware support monitor mode. USB HID gadget support is distinct from Bluetooth functionality; `CONFIG_HIDRAW` alone is not a USB keyboard gadget. Driver names and adapter revisions matter (for example, AR9271 uses `ath9k_htc`). NetHunter warns that external-card support depends on kernel/driver and USB OTG/power conditions. Sources: [NetHunter components](https://www.kali.org/docs/nethunter/nethunter-components/), [wireless-card guidance](https://www.kali.org/docs/nethunter/wireless-cards/), [Linux USB gadget testing](https://docs.kernel.org/usb/gadget-testing.html).

### 3. Internal Wi-Fi “impossible” claim

**Verdict: Overstated.** The published tablet specs do not identify the exact Wi-Fi core or prove its monitor-mode capability. Nexmon’s documented support is not a ready-made solution for this MediaTek device, but that does not prove no private or custom driver path exists. Root does not automatically provide raw packets, monitor mode, injection, or successful network attacks. The user’s own current `iw list` proves only that the currently loaded driver does not advertise standard monitor mode.

### 4. Internal firmware patching roadmap

**Verdict: Reverse engineering is a legitimate research avenue; the proposed patch steps are conjecture.** `cyrozap/mediatek-wifi-re` is useful for researching certain MediaTek Wi-Fi firmware formats, but it does not prove that its exact parser, ISA, firmware layout, or protections apply to this tablet. The PDF did not establish the tablet’s firmware paths, signature enforcement, existence of an “injection-drop” branch, or that NOPing a branch would enable monitor mode. Source: [mediatek-wifi-re](https://github.com/cyrozap/mediatek-wifi-re).

### 5. Secure Boot explanation

**Verdict: General Verified Boot facts were mixed with unverified Wi-Fi-firmware claims.** Android Verified Boot validates configured boot/Android partitions; that does not prove that this tablet’s separate Wi-Fi firmware is verified by the same chain, uses a particular OEM RSA key, or is rooted in a particular eFuse. The specific Wi-Fi firmware validation path remains unknown. Sources: [Android Verified Boot](https://source.android.com/docs/security/features/verifiedboot), [device state](https://source.android.com/docs/security/features/verifiedboot/device-state).

### 6. Nexmon and chip research

**Verdict: Correct that no ready-made Nexmon solution is established; the leak and lab-hardware narrative is not substantiated.** Nexmon focuses on supported Broadcom/Cypress chips. Its cited research does not prove the PDF’s alleged source-code leak. A separate MediaTek EMFI experiment must not be generalized to this tablet. Sources: [Nexmon](https://github.com/seemoo-lab/nexmon), [Nexmon research](https://arxiv.org/abs/1601.07077), [Quarkslab Broadcom analysis](https://blog.quarkslab.com/reverse-engineering-broadcom-wireless-chipsets.html).

### 7. Bug bounty and key-leak claims

**Verdict: Disclosure-program distinction is broadly right; incident descriptions are conflated.** MediaTek’s public VDP does not promise a monetary reward; a separate private bounty may have eligibility/reward rules. Ledger’s EMFI work concerns a Dimensity 7300 / MT6878 boot ROM, not a master signing-key leak or this tablet’s Wi-Fi firmware. Check Point’s Xiaomi/Tencent Soter report concerns TEE/payment-signing-key vulnerabilities, not an OEM firmware-signing-key leak. Sources: [MediaTek VDP](https://corp.mediatek.com/vulnerability-disclosure-policy), [MediaTek security contact](https://www.mediatek.com/security-contact), [Ledger Donjon](https://www.ledger.com/blog-is-your-smartphones-hardware-safe), [Check Point](https://research.checkpoint.com/2022/researching-xiaomis-tee/).

### 8. Mythos/AI cyber capability claims

**Verdict: Controlled-evaluation results were generalized beyond their evidence.** The UK AISI CTF and cyber-range results are controlled simulations, not proof of reliable attacks on arbitrary hardened systems. A reported 100-million-token inference budget is not the same thing as a context window. Mythos access and safeguard claims need to specify the model version and access program. Sources: [UK AISI evaluation](https://www.aisi.gov.uk/blog/our-evaluation-of-claude-mythos-previews-cyber-capabilities), [Anthropic report](https://red.anthropic.com/2026/mythos-preview/), [Project Glasswing](https://www.anthropic.com/glasswing).

### 9. MCP/GitHub Actions/Drive/ReAct architecture

**Verdict: Components are real; automation and security claims were oversold.** MCP provides a tool protocol, not an autonomous reasoning guarantee. GitHub Actions can support CI fuzzing but has billing, runtime, retention, permissions, and secret-handling constraints. Actions compute is generally dollar-denominated in billing docs; student allowances are separate. Drive mounts through rclone are remote-backed and may delay writes; they are not robust real-time shared storage by default. OSS-Fuzz and CIFuzz are separate facilities requiring project/harness integration. Sources: [MCP filesystem server](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem), [Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions), [student benefits](https://github.com/education/students), [rclone Drive](https://rclone.org/drive/), [OSS-Fuzz](https://google.github.io/oss-fuzz/getting-started/new-project-guide/).

### 10. Revised autonomous research architecture

**Verdict: Plausible design outline, not a verified autonomous vulnerability-research system.** CI can run fuzz targets and collect crashes, but fuzzing does not guarantee bugs, root cause, exploitability, or exploit chains. Human review, authorization boundaries, reproducibility, and secure secret handling remain necessary. The PDF presented an aspiration as though components would reliably self-orchestrate.

### 11. Wi-Fi firmware reverse-engineering roadmap

**Verdict: Useful tooling ideas, but the claimed patch target and signature bypass are unverified.** The MediaTek parser repository covers certain firmware formats, not necessarily this tablet’s exact firmware. The presence of a MediaTek driver does not prove that an injection-blocking branch exists or that a patch would enable a desired mode. Do not conflate Verified Boot with independent Wi-Fi firmware validation.

### 12. Reverse-engineering tools

**Verdict: Most named tools are real; they are not turnkey emulators or device-specific compatibility proof.** Ghidra, radare2, IDA, Kaitai, Binwalk, Unblob, Unicorn, Qiling, and PyGhidra have relevant analysis uses, but architecture and target support must be checked. Current Ghidra supports NDS32; Unicorn’s architecture list does not include NDS32. Qiling/Unicorn do not automatically model the tablet’s radio, driver, firmware, or hardware interactions. IDA Free is limited to non-commercial use. Sources: [Ghidra](https://github.com/NationalSecurityAgency/ghidra), [Unicorn](https://github.com/unicorn-engine/unicorn), [Qiling](https://github.com/qilingframework/qiling), [IDA Free FAQ](https://hex-rays.com/faqs/can-i-use-ida-free-for-work-or-freelancing-1).

## Progress toward the device goal

“Complete pentesting device with all hardware access” is not a single software switch. Each radio and peripheral needs compatible hardware, kernel/driver support, a working data path, and separate validation. Based on the evidence available:

| Capability | Current status | Confidence |
|---|---|---|
| Rooted Android with NetHunter installed | User reports this is already complete | User-reported |
| Built-in Wi-Fi managed/AP operation | Interfaces and modes are exposed by the running driver | Confirmed from supplied diagnostics |
| Standard `nl80211` monitor mode | Not advertised by `iw list` | Confirmed absent from current interface |
| Private internal Wi-Fi RX/ICS path | Matched WLAN module contains a conditional RX producer that frames copied RX-buffer bytes with a custom 12-byte header and calls the ICS ring writer; companion ring/device code is present. Runtime confirms the writer provider is loaded and `/dev/fw_log_ics` exists (`0600 root:root`), but no writer invocation or ring content was observed. | Strong static evidence for implementation; runtime confirms endpoint/provider only; activation and payload unverified |
| ICS logger selection/access | Static `ReorganizePort` analysis intersects `wifi,ics` customization with `bt,wifi,gps,mcu` property and predicts only `WIFI`; no ICS FD was observed. The UID-2000 logger cannot pass DAC on the ICS node. | Static selection prediction plus runtime absence of observed ICS FD; no active ICS reader established |
| Usable raw 802.11 capture and channel control | No completed capture, decoded full frame, Radiotap record, or channel-control result. The custom RX payload's completeness and metadata are unknown. | Unproven; standard `nl80211` monitor mode is absent from current `iw` capabilities |
| Radiotap / `tcpdump`-usable capture | No interface or format demonstrated | Unproven |
| Packet injection | No injection path or successful test demonstrated | Unproven |
| Bluetooth stack | Android Bluetooth service is ON and `bluetooth@1.1-s` holds `/dev/stpbt` open; `/sys/class/bluetooth` is empty and HCI tools were absent | Vendor HAL transport use confirmed; raw HCI and RF-sniffing unknown |
| Other tablet hardware (USB/OTG/HID, GPS, cameras, etc.) | Not assessed in this report | Unknown; assess each separately |

**How close are you?** The setup stage is largely done: you have root, NetHunter, and working built-in Wi-Fi. The matched WLAN module contains a conditional private RX producer that submits custom-framed bytes to the ICS writer; the companion module and root-only character device are present at runtime, but no invocation or ring data was observed. The Android Bluetooth HAL is using its vendor STP transport. Static analysis identifies `connsyslogger` as the intended reader. The active customization asks for `wifi,ics`, but the dedicated-port property restricts the candidates to `bt,wifi,gps,mcu`; analysis of `ReorganizePort` predicts the effective list contains Wi-Fi only, not ICS. Actual ICS records, decoded frame contents, monitor-style use, injection, and Bluetooth RF-sniffing remain unverified. The tablet is a promising research platform, **not yet a verified all-hardware pentesting device**. A percentage would be misleading because “all hardware access” spans independent capabilities. No device-node reads, undocumented ioctls, or state-changing tests are recommended until a documented access path and record semantics are clear. No external adapter is assumed or recommended here.

## Roadmap: monitor mode, injection, Bluetooth, and peripherals

This is a gated plan, not a claim that every capability can be enabled on this hardware. The current snapshot has no standard `nl80211` monitor mode. A private RX-to-ICS producer exists in the matched driver, but its payload format is undecoded, ICS is predicted not to be selected by the logger configuration, and the ICS device node must not be read under the current safety constraints. Keep work on the tablet read-only until the private interface and recovery behavior are documented. Do not flash/modify kernel or firmware, change permissions/properties, issue undocumented ioctls, or guess `SNIFFER` values.

### Stage 1 — Freeze the known-good baseline (read-only)

- Preserve the already-collected device/build fingerprint, `iw list`/`iw dev`, module list, node metadata, service state, relevant SELinux policy/init excerpts, and hashes. The Wi-Fi driver and firmware hashes already match their reported device files; the companion `wmt_chrdev_wifi.ko` still lacks a device-side hash comparison.
- Before any later experimental work is even considered, retain the exact stock boot/vendor_boot images, matching vendor modules, and a recovery route. Do not change the running setup as part of this stage.
- Keep identifying values (addresses, SSIDs/BSSIDs, IPs, nearby-device names) out of any public report.

**Gate:** Exact device/build/module identity and a viable recovery path are recorded. This is preparation only; it does not establish monitor capability.

### Stage 2 — Decide whether the internal radio has a supported monitor path (static analysis)

- Find source or vendor documentation that matches this exact kernel/module/firmware build. Drive searches found the matching driver, firmware, companion module, logger/config files, and device snapshots, but no matching driver source or documented `SNIFFER`/ICS format.
- In the exact driver/source, trace the advertised `cfg80211`/nl80211 operations and whether a monitor interface type is registered. If it is not registered, ordinary Android configuration or NetHunter cannot create standard monitor mode by itself.
- For the private route, continue read-only cross-references from `priv_driver_sniffer` through the two state bytes, firmware command `0x93`, firmware-side handling, and `nicRxProcessRFBs`. Identify what the RX buffer actually contains, whether it includes complete 802.11 headers/control frames/FCS, and whether channel/rate/timestamp metadata exists. The 12-byte prefix and ring writer alone answer none of those questions.
- Determine a documented start/stop/recovery sequence and the intended supported consumer. The current static logger selection predicts only `WIFI`, not `ICS`; `/dev/fw_log_ics` is `0600 root:root`, and the observed logger has no ICS FD. Do not work around this by changing permissions or properties or reading the node. If no documented, safe ICS consumer/access path is found, stop treating the private path as a usable capture interface.

**Gate:** A supported interface, field meanings, payload schema, consumer, access permissions, and a recovery procedure are documented. Otherwise internal monitor mode remains unresolved—not “almost enabled.”

### Stage 3 — Choose an implementation path

1. **If exact source/documents confirm standard monitor support is already present:** use only the documented interface and stock-supported configuration, then proceed to controlled passive validation.
2. **If the private ICS path is documented as complete-frame capture:** document the format and supported consumer, but runtime use remains blocked by the current explicit no-read restriction on `/dev/fw_log_ics`. Do not invoke a reader that consumes that node unless the user explicitly revises that boundary after the interface and recovery behavior are established. Do not infer pcap/Radiotap compatibility from the custom magic or firmware strings; write a parser only after the schema and loss behavior are known.
3. **If neither internal path is supported:** the remaining options are a vendor-supported driver/firmware update (outside the current no-modification scope) or a separate, proven monitor-capable USB radio. For an external radio, first verify the exact chipset/revision, Android kernel driver availability, USB-host/OTG and power support, and NetHunter integration from evidence; do not assume generic adapter compatibility or buy based on chipset family alone.

**Gate:** Select one documented path. Do not mix a speculative private command with unrelated third-party recipes for another Gen4m device.

### Stage 4 — Validate passive capture (only after Stage 2/3 gates pass)

On a device and network you own or are explicitly authorized to assess, use a controlled AP and client. This stage applies to a standard monitor interface or a separately supported external radio; the private ICS route is blocked from runtime testing by the current no-read restriction. First verify that the supported interface enters the documented capture mode, can select/hold the intended channel, and has a reliable stop/recovery procedure. Then capture only controlled traffic and verify in an offline decoder that records contain valid 802.11 frame-control/header fields and the expected metadata. Confirm whether frames are management, control, and/or data; whether FCS is present; whether records are truncated/dropped; and whether capture works across a restart. A `tcpdump` file or interface name alone is not proof of valid monitor capture. Do not read `/dev/fw_log_ics` or activate undocumented controls as part of this plan.

**Acceptance:** Repeatable passive reception of expected frames on a controlled channel, correctly decoded with documented metadata and a clean recovery path. Otherwise record the precise failure and do not label the feature monitor mode.

### Stage 5 — Assess packet injection separately

Monitor reception does not imply transmission of arbitrary frames. First establish a documented TX/injection API and its frame constraints from the exact driver/firmware. Only then, and only on an isolated lab network under authorization, use a benign test that does not disrupt third parties; verify the emitted frame and device recovery independently. The present `SNIFFER`/ICS evidence proves no injection capability. No deauthentication, disruption, or guessed command tests are part of this roadmap.

### Stage 6 — Assess Bluetooth sniffing as a separate radio capability

- Current evidence shows Android Bluetooth can be ON and the HAL uses `/dev/stpbt`; the snapshots show no `hci0` sysfs node or available HCI utility. Driver HCI/BT-log symbols and a vendor transport prove transport/diagnostic plumbing, not over-the-air sniffing.
- Determine from exact controller/firmware documentation whether a supported controller diagnostic or monitor mode exists and whether it covers only the tablet’s own host-controller traffic. Android BTSnoop/HCI logs, if available through documented controls, represent host/controller traffic and are not equivalent to passively capturing arbitrary nearby Bluetooth devices over the air.
- If the internal controller has no documented RF-sniffer path, treat a separately supported Bluetooth sniffer as a distinct hardware option and validate its protocol/band coverage; do not infer sniffing from Bluetooth ON or `/dev/stpbt` being open.

**Acceptance:** Explicitly distinguish (a) host HCI logging, (b) the tablet’s own connection events, and (c) over-the-air capture of other authorized test devices. Claim only the level actually demonstrated.

### Stage 7 — Inventory other hardware independently

Check USB host/OTG, HID gadget support, GPS, cameras, and any other required feature separately against the running kernel/configuration, Android service/device exposure, and a safe validation method. `HIDRAW`, a GPS device node, or a vendor module name alone does not establish the end-to-end capability. Keep this inventory separate from Wi-Fi monitor mode.

### Final decision rule

The most practical near-term route is to finish **static** decoding of the exact internal RX/ICS path and determine whether a documented supported consumer exists. If that cannot establish complete frames and recoverable controls, classify internal monitor mode as unproven and prefer a documented external radio or supported vendor implementation. Even if static analysis succeeds, runtime use of the ICS node remains out of scope unless the user explicitly revises the no-read constraint. Injection, Bluetooth RF sniffing, and other peripherals each require their own independent evidence and acceptance tests. At no point should a speculative command, permission change, kernel/firmware modification, or read of `/dev/fw_log_ics` be used to bridge missing evidence under the current constraints.

## References

- Kali NetHunter overview and editions: https://www.kali.org/docs/nethunter/
- NetHunter components: https://www.kali.org/docs/nethunter/nethunter-components/
- NetHunter wireless cards: https://www.kali.org/docs/nethunter/wireless-cards/
- Xiaomi Redmi Pad SE 4G specs: https://www.mi.com/in/product/redmi-pad-se-4g/specs/
- Xiaomi kernel source: https://github.com/MiCode/Xiaomi_Kernel_OpenSource
- Android Verified Boot: https://source.android.com/docs/security/features/verifiedboot
- Android app execution behavior: https://developer.android.com/about/versions/10/behavior-changes-10
- MediaTek Wi-Fi firmware research tools: https://github.com/cyrozap/mediatek-wifi-re
- Unverified other-device Gen4m `MONITOR` guide: https://github.com/Minecraftcon/realme-reverse-engineering/blob/main/RMX3171/wifi/MEDIATEK_WIFI_MONITOR_REVERSE_ENGINEERING.md
