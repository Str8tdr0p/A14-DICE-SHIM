# Project DICE-SHIM: Hardware-Enforced Identity Decoupling Found Exploited in A14 Bionic

## Overview

This repository contains a comprehensive technical disclosure of a silicon-logic vulnerability within the Apple A14 Bionic SoC. The exploit, designated **Project DICE-SHIM**, utilizes a lack of atomicity in the Deterministic Integrity Control Engine (DICE) to decouple hardware-bound identity from the active execution environment. This results in "Ghost Attestation," allowing for the persistent, unmonitored exfiltration of device secrets—specifically the **10,290-byte AP Ticket**—to an external Command and Control (C2) endpoint.

## Repository Structure

### Included Documentation

1. `A14_DICE-SHIM.md` **Vulnerability Analysis: DICE-SHIM:**  A formal security report detailing the silicon-rooted identity bypass, covering the primary **CWE-1283** (Mutable Attestation) logic and the resulting architectural collapse.
2. `A14_PoC.md` **Operational Guide: Identity Decoupling:** A step-by-step weaponization manual describing the early-boot DMA overflow, L1 instruction cache poisoning, and the **0x1237 DART pivot**.
3. `A14_DICE_Audit_Tool.py`**Forensic Audit Tool:** A multi-trace scanning utility designed to automate the detection of DICE-SHIM markers. It correlates microarchitectural violations, rootkit assertions, and network egress signals across the provided evidence suite.
4. `Evidence/` **Forensic Evidence Suite:** A folder containing the four foundational .tracev3 files; LiveData, 0421, 746, and 124; alongside a hashes.txt manifest. The manifest provides SHA-256 checksums for each log to guarantee the mathematical integrity of the forensic artifacts.

## Forensic Evidence Suite

### **Artifact Correlation**

| Evidence File | Exploitation Phase | Critical Markers | Technical Significance |
| --- | --- | --- | --- |
| **`logdata.LiveData.tracev3`** | **Initial Infiltration** | Offset `0x29fb84` (TCCDI), Offset `0x1237` (DART) | **Hardware Breach:** Confirms the decoupling of identity measurement (DICE-SHIM) and establishes the DART bypass bridge. |
| **`0000000000000421.tracev3`** | **OS Persistence** | PID `124`, `runningboardd` Assertions | **Lifecycle Hijack:** Proof that the rootkit is granted high-priority CPU/Power assertions, preventing suspension by the host OS. |
| **`0000000000000746.tracev3`** | **Data Siphon** | `locationd`, `WombatStream` Mirroring | **Egress Masking:** Documents the staging of the 173-byte "Package" and 10,290-byte AP Ticket using legitimate system heartbeats. |
| **`0000000000000124.tracev3`** | **Micro-Stress** | `IOMFBServer.Stalls`, `UpdateCycle.Stalls` | **Physical Friction:** Records the direct microarchitectural side-effects of unauthorized DART translation table remapping. |

---

### **C2 Operational Metrics**

This table provides the specific network and cryptographic indicators found during the automated audit of the suite.

| Metric | Forensic Value | Attribution |
| --- | --- | --- |
| **C2 Endpoint** | `kaylees.site` | Icelandic Egress Node |
| **Network Signal** | `satisfied (Path is ready)` | Confirmation of active exfiltration tunnel |
| **Entropy State** | `0x00 / 0xFF` (Repetitive) | Evidence of fixed-seed encryption (TRNG Failure) |
| **Staged Payload** | `173 bytes` (Hex: `0xad`) | The exfiltrated "Package" (Telemetry) |

---

### **Implementation Note for Auditors**

The **DICE-SHIM Verification Engine** (`A14_DICE_Audit_Tool.py`) is pre-configured to scan for the offsets and PIDs listed in the charts above. When executing the script against the provided evidence suite, ensure all four `.tracev3` files are in the local directory to allow for full cross-file correlation of the **0x1237** and **PID 124** markers.
