# Research findings: NetHunter, ANDRAX, and the Redmi Pad SE 4G

**Prepared:** 2026-11-12

**Scope:** Fact-check of the 17-page “Kali NetHunter vs ANDRAX Comparison” PDF, plus device-specific analysis of the user’s rooted Redmi Pad SE 4G internal Wi-Fi driver.

**Important:** The device findings below are based on the screenshots and command output supplied by the user. They are not a claim that the internal Wi-Fi has been successfully used for monitor-mode capture or injection.

## Executive summary

- The PDF gets some general distinctions right, but repeatedly turns generic platform facts into unsupported claims about the Redmi Pad SE 4G. Its categorical claims about the tablet’s internal Wi-Fi and Wi-Fi firmware verification are not established.
- The tablet is model **24076RP19I**, running Android 14 / HyperOS **1.0.1.0.UHYINXM**, kernel **5.10.198-android12-9+**, on MediaTek Helio G85. It is rooted and has NetHunter installed.
- Its current MediaTek `wlan_drv_gen4m` driver advertises managed, AP, P2P, and IBSS modes through `iw`; it does **not** advertise standard `nl80211` monitor mode.
- More importantly, the exact driver binary contains `priv_driver_sniffer`, `wlanoidSetIcsSniffer`, the `SNIFFER` command string, and an ICS-related command path. The disassembly shows a private parser requiring ten hyphen-separated numeric fields (the fifth parsed as hexadecimal), followed by an 80-byte driver structure passed to a handler that sends firmware command `0x93`.
- This is strong evidence of a private **sniffer-related** driver function and makes internal capture technically plausible. It does **not yet prove** that the function provides raw over-the-air 802.11 frames, a standard monitor/radiotap interface, or packet injection. Do not guess or invoke the command until its field meanings and output path are understood.

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

## Recommended next steps for the tablet

1. **Do not flash a new kernel, patch firmware, unload `wlan_drv_gen4m`, or send guessed `SNIFFER` values.** The command’s field meanings have not been decoded.
2. Treat this as a static-analysis task first. Obtain the matching MediaTek Gen4m driver source if available, or analyze the module’s command handler and the firmware-side handling of command `0x93`. The `SNIFFER` parser format is known; the semantic mapping of its fields is not.
3. Establish what data path ICS provides: a raw 802.11 netdev/radiotap interface, an internal diagnostic log, CSI/IQ capture, or something else. Do not label it “monitor mode” until raw frame reception is demonstrated.
4. If a valid syntax and safe enable/disable sequence are recovered, test **passive reception only** on a controlled AP and a client the user owns. Confirm captured frame type/channel and a reliable stop/recovery path before considering other capabilities.
5. Test packet injection separately. Support for a private sniffer path does not prove injection support.
6. Keep a copy of the matching stock boot/vendor_boot images and the original module before any later changes. Any testing must be on networks the user owns or is explicitly authorized to assess.

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
