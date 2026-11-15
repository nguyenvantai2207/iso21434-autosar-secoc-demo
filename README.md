# AUTOSAR SecOC & ISO/SAE 21434 — Automotive CAN Bus Door Lock Security Demo

An interactive simulation and real-hardware demonstration of **Automotive CAN Bus Cybersecurity** for a Car Door Unlock/Lock system, engineered in alignment with **AUTOSAR Classic (`SecOC` + `IdsM`)** and **ISO/SAE 21434**.

---

## 1. Overview & Motivation

Modern vehicles rely on Controller Area Network (**CAN Bus**) to exchange safety- and security-critical commands between Electronic Control Units (ECUs). Classical CAN (ISO 11898) lacks built-in encryption or authentication, leaving legacy systems vulnerable to **Sniffing**, **Replay Attacks**, and **Frame Spoofing/Injection**.

This project demonstrates side-by-side how **AUTOSAR Secure Onboard Communication (`SecOC`)** and **Intrusion Detection System Manager (`IdsM`)** mitigate these threats in real time:

| Operating Mode | CAN Frame Payload (`ID: 0x0120`) | Security Posture |
| :--- | :--- | :--- |
| **1. Unsecured Mode**<br>(`SW_SEC` = HIGH / Right) | **DLC = 1 byte**<br>- `Byte 0`: Command (`0x01` = Unlock, `0x02` = Lock) | **Vulnerable.** Any attacker on the CAN bus can sniff a single `0x01` frame and replay/inject it to unlock the vehicle doors. |
| **2. ISO/SAE 21434 Secured Mode**<br>(`SW_SEC` = LOW / Left) | **DLC = 8 bytes (AUTOSAR SecOC Secured I-PDU)**<br>- `Byte 0`: Command (`0x01` = Unlock, `0x02` = Lock)<br>- `Byte 1..2`: **Freshness Value** (16-bit Big-Endian Rolling Counter)<br>- `Byte 3..6`: **Truncated MAC** (Top 32 bits of `SHA-256(SECRET_KEY \|\| Cmd \|\| Counter)`)<br>- `Byte 7`: Padding (`0x00`) | - **Anti-Replay Protection:** Rejects frames if `rx_counter <= last_valid_counter` $\rightarrow$ Triggers **IdsM Alert** (`SECOC_FRESHNESS_FAIL`).<br>- **Anti-Spoofing Protection:** Rejects frames if `rx_mac != expected_mac` $\rightarrow$ Triggers **IdsM Alert** (`SECOC_MAC_VERIFICATION_FAIL`). |

---

## 2. System Architecture

### A. Wokwi Simulation Architecture (Single-Workspace Full CAN Bus)
Because the Wokwi VS Code Extension simulates one main MCU per diagram, the simulation uses an **Arduino Nano (`bcm`)** paired with **two custom WebAssembly (`.wasm`) chips**:
1. **`chip-central_ecu` ([chips/central_ecu.chip.c](chips/central_ecu.chip.c)):** Reads the `UNLOCK`/`LOCK` pushbuttons and the `SecOC Mode` slide switch, computes the 16-bit Freshness Counter and SHA-256 Truncated MAC, and transmits frames over the virtual CAN bus.
2. **`chip-mcp2515` ([chips/mcp2515.chip.c](chips/mcp2515.chip.c)):** Cycle-accurate byte-level SPI emulation of the Microchip MCP2515 CAN controller (compatible with `autowp/autowp-mcp2515`), bridging SPI transactions from the BCM MCU to the virtual CAN bus.
3. **Built-in Cando-style Analyzer & Hacker Injector ([src/bcm_ecu.cpp](src/bcm_ecu.cpp)):** Streams real-time CAN bus traffic in a formatted table (`Time`, `Channel`, `Dir`, `CAN ID`, `Type`, `DLC`, `Data (Hex)`) and accepts live frame injections directly from the Serial Monitor.

### B. Real Hardware Architecture
For physical bench testing, the repository provides separate PlatformIO environments:
- **`env:bcm_nano` ([src/bcm_ecu.cpp](src/bcm_ecu.cpp)):** Flashed to an **Arduino Nano** + MCP2515 CAN Module + SG90 Servo (`D9`) + Valid LED (`D6`) + IdsM Alert LED (`D7`).
- **`env:central_uno` / `env:central_mega` ([src/central_ecu.cpp](src/central_ecu.cpp)):** Flashed to an **Arduino Uno / Mega2560** + MCP2515 CAN Module + Unlock Button (`D4`) + Lock Button (`D3`) + Security Switch (`D5`).
- **Attacker / Bus Analyzer Node:** A PC connected via a USB-to-CAN adapter running **Cando** or Linux `can-utils` (`candump` / `cansend`) on the physical `CAN_H` / `CAN_L` twisted pair.

---

## 3. Repository Structure

```text
iso21434-autosar-secoc-demo/
├── chips/                          # Wokwi Custom Chips (C source + compiled WebAssembly)
│   ├── central_ecu.chip.c          # Central ECU custom chip (Buttons, Switch, SHA-256 SecOC, CAN TX)
│   ├── central_ecu.chip.json       # Pin definitions for central_ecu chip
│   ├── central_ecu.chip.wasm       # Pre-compiled WebAssembly binary for central_ecu
│   ├── mcp2515.chip.c              # MCP2515 SPI-to-CAN controller custom chip
│   ├── mcp2515.chip.json           # Pin definitions for mcp2515 chip
│   ├── mcp2515.chip.wasm           # Pre-compiled WebAssembly binary for mcp2515
│   └── wokwi-api.h                 # Wokwi Custom Chip C API header
├── src/                            # Arduino / PlatformIO C++ Firmware
│   ├── bcm_ecu.cpp                 # BCM ECU firmware (SecOC Verifier, IdsM, Servo, Cando CLI)
│   └── central_ecu.cpp             # Central ECU firmware (for physical Arduino Uno/Mega deployment)
├── diagram.json                    # Wokwi schematic & hardware layout
├── wokwi.toml                      # Wokwi configuration & RFC2217 serial bridge
├── platformio.ini                  # PlatformIO build environments & dependencies
└── README.md                       # Project documentation
```

---

## 4. Prerequisites & Setup

1. **Visual Studio Code** with the following extensions installed:
   - [PlatformIO IDE](https://marketplace.visualstudio.com/items?itemName=platformio.platformio-ide)
   - [Wokwi Simulator](https://marketplace.visualstudio.com/items?itemName=Wokwi.wokwi-vscode) (requires a free Wokwi license activated in VS Code)
2. **Build the BCM Firmware:**
   ```bash
   pio run -e bcm_nano
   ```
3. *(Optional)* **Recompile Wokwi Custom Chips** (only needed if you modify `chips/*.chip.c`):
   ```bash
   wokwi-cli chip compile chips/mcp2515.chip.c -o chips/mcp2515.chip.wasm
   wokwi-cli chip compile chips/central_ecu.chip.c -o chips/central_ecu.chip.wasm
   ```

---

## 5. Step-by-Step Interactive Demo Guide

### Step 1: Start the Simulation
1. Open the Command Palette (`Ctrl+Shift+P` or `Cmd+Shift+P`) and run **`Wokwi: Start Simulator`**.
2. The integrated Serial Monitor will display the **Cando CAN Bus Analyzer** header:
   ```text
   ======================================================================
     [Cando CAN Bus Analyzer & AUTOSAR SecOC/IdsM Monitor - 500 kbps]
     Inject format: '120 01' or '120 01 00 01 8E 86 5F 48 00'
   ======================================================================
      Time(s)  | Ch   | Dir | CAN ID | Type | DLC | Data (Hex)
   ------------+------+-----+--------+------+-----+----------------------
   ```

### Step 2: Scenario A — Unsecured Mode & Hacker Injection Attack
1. Flip the **`SecOC Mode`** slide switch to the **Right** (Unsecured Mode).
2. Click the green **`UNLOCK`** button and yellow **`LOCK`** button on the diagram:
   ```text
         1.842 | can0 | RX  | 0x0120 | STD  | [1] | 01 
      [BCM UNSECURED] Command Accepted!  -> Action: UNLOCKED (Servo 90 deg)
         3.210 | can0 | RX  | 0x0120 | STD  | [1] | 02 
      [BCM UNSECURED] Command Accepted!  -> Action: LOCKED (Servo 0 deg)
   ```
3. **Simulate a Hacker Attack:** In the Serial Monitor input field, type the captured unlock frame and press `Enter`:
   ```text
   120 01
   ```
   - **Result:** The BCM accepts the injected frame (`Dir: INJ`), illuminates the green **Valid LED**, and rotates the **Door Lock Servo to `90°` (Unlocked)**. The vehicle is compromised!

### Step 3: Scenario B — ISO/SAE 21434 Secured Mode (AUTOSAR SecOC + IdsM)
1. Flip the **`SecOC Mode`** slide switch to the **Left** (Secured Mode).
2. Click **`UNLOCK`** then **`LOCK`** on the diagram. Observe the 8-byte SecOC frames containing the 16-bit Freshness Counter (`00 01`, `00 02`) and 32-bit SHA-256 Truncated MAC:
   ```text
        10.412 | can0 | RX  | 0x0120 | STD  | [8] | 01 00 01 8E 86 5F 48 00 
      [BCM SECOC OK] Counter=1  -> Action: UNLOCKED (Servo 90 deg)
        12.905 | can0 | RX  | 0x0120 | STD  | [8] | 02 00 02 97 D9 93 EC 00 
      [BCM SECOC OK] Counter=2  -> Action: LOCKED (Servo 0 deg)
   ```
3. **Attack 1 — Replay Attack (Re-sending a captured valid Unlock frame):**
   - Copy the previous valid Unlock frame (`Counter = 00 01`) and send it in the Serial Monitor:
     ```text
     120 01 00 01 8E 86 5F 48 00
     ```
   - **Result:** Blocked! Because `rx_counter (1) <= last_valid_counter (2)`, the door remains locked, the red **`IdsM Alert` LED** flashes 4 times, and the monitor logs:
     ```text
     [IdsM SECURITY EVENT] SECOC_FRESHNESS_FAIL (Replay Attack Blocked!)
     ```
4. **Attack 2 — Spoofing Attack (Incrementing the Counter without the Secret Key):**
   - Modify the counter bytes to `00 05` (greater than `00 02`) while keeping or guessing the MAC bytes:
     ```text
     120 01 00 05 8E 86 5F 48 00
     ```
   - **Result:** Blocked! Freshness verification passes, but the SHA-256 MAC check fails. The red **`IdsM Alert` LED** flashes 4 times and logs:
     ```text
     [IdsM SECURITY EVENT] SECOC_MAC_VERIFICATION_FAIL (Spoofing Blocked!)
     ```
