# CLAUDE.md

## What This Is

Cleotilde is the ESP32 "face" of the **Cleotilde Teleonome**, a network security / analyzer that watches the
OpenWrt One router (design: `~/Data/OpenWrtOne/documents/05-teleonome-design.md`). It runs on **Wally 17 + Paula shield**,
plugged into the Cleotilde Pi by USB (`/dev/ttyUSB0`, CP2104). The Pi decides what the LEDs and OLED show; the board
adds its own judgement (WiFi status, heartbeat, Pi-silent warning) and measures its own power input (INA219).

Based on `Projects/Annabelle/Annabelle.ino`: same secret manager, `WifiManager` base class and RTC code. No LoRa,
telepathons, weather or DataManager. Wally has no firmware of its own, so **everything is in `Cleotilde.ino`**, including
the `CleotildeWifiManager` subclass (no new class in DigitalStablesEsp32Lib).

## Hardware (Wally 17 + Paula)

| Function | Pin / address |
|---|---|
| 5 × WS2812 LEDs | GPIO19 |
| 2.42" SSD1309 OLED | I²C 0x3C |
| PCF8563 RTC | I²C 0x51, 1 Hz CLKOUT → GPIO4 |
| INA219 (power input, 50 mΩ shunt) | I²C 0x45 expected; firmware scans 0x40–0x47 and reports what it found |
| DS18B20 (board temp + serial number) | GPIO27 |
| Slide switch left / right | GPIO32 / GPIO33 (active low) |
| RTC coin cell divider (1M/2M) | GPIO36 |
| OP_MODE | GPIO34 |
| Sleep switch (held HIGH) | GPIO26 |

Daffodil.ino notes the Wally INA219 is "absent on boards without the current-sensor upgrade (builds before 18)".
If GetSensorData field 14 is 0, this board has none.

## Defaults on a brand-new board

Joins `MainRouter24` (open) as hostname **CleotildeESP32**, not `Cleotilde`, because the Pi is `Cleotilde.local`.
Change with `ConfigWifiSTA#ssid#pass#host` over serial or the form on `http://<ip>/`.

## LEDs

| LED | Meaning (set by the Pi) |
|---|---|
| 1 | Internet |
| 2 | Router health |
| 3 | Wi-Fi |
| 4 | Devices / security |
| 5 | Teleonome |

Before the Pi sends `SetLeds`: LED 1 = WiFi (G connected, B AP mode, blinking R down), LED 5 = heartbeat.
After: the Pi owns all five; if the Pi goes quiet the board turns LED 5 yellow after 2 min, red after 10 min.
`ReleaseLeds` hands them back to the board.

## OLED

Switch **left**: the Pi's pages (up to 6, rotating every 5 s). Switch **right**: the board's own status page
(time, IP/RSSI, input V/mA, board temperature, RTC cell, uptime, heap, reset reason, firmware).

## Serial protocol (115200, one command per write, answers end with `Ok-<cmd>` or `Failure-...`)

| Command | Answer |
|---|---|
| `Ping` | `Ok-Ping` |
| `GetSensorData` | one `#` line, see below |
| `SetLeds#G#Y#r#O#G` | colour per LED: G Y R B W O(ff); lower case = blink |
| `SetLed#3#R` | one LED (1–5) |
| `ReleaseLeds` | board shows its own status again |
| `Oled#page#title#l1#l2#l3#l4#l5#l6` | page 1–6, ~21 chars per line; empty title clears the page |
| `ClearOled` | |
| `Relay#ch#CYCLE#sec` | `Failure-NoRelayHardware` until Cleotilde Build 1 |
| `PulseStart` / `PulseFinished` | LED 5 blinks blue during a pulse (before the Pi owns the LEDs) |
| `Start …` / `End …` (life cycle events) | `Ok-<event>` |
| `GetTime`, `SetTime#d#m#yy#dow#hh#mm#ss`, `SetTimeFromInternet` | as Annabelle |
| `GetCommandCode`, `GetSecret`, `SetSecret#base32#digits#period` | TOTP, as Annabelle |
| `VerifyUserCode#123456` | `Ok-Valid Code` / `Failure-Invalid Code`. Doorbell: any 30 s step in the last 3 min (+1 ahead), each step once; 5 wrong in an hour = locked for an hour |
| `ConfigWifiSTA#ssid#pass#host`, `ConfigWifiAP#ssid#pass#host`, `GetIpAddress`, `RestartWifi`, `ScanNetworks` | |
| `GetSerialNumber`, `GetFirmware`, `ResetInfo`, `GetOperationMode`, `Reboot`, `Flush`, `debug#1` | |

GetSensorData fields (append only, never reorder):
`0 deviceTypeId · 1 serialNumber · 2 secondsTime · 3 inputVoltage · 4 inputCurrentmA · 5 inputPowermW · 6 boardTemperature ·
7 rtcBatVolt · 8 wifiRssi · 9 ipAddress · 10 uptimeSec · 11 freeHeap · 12 minFreeHeap · 13 switchPosition (L/R) ·
14 ina219Address (0 = none) · 15 resetReason · 16 firmware · 17 relayHardware (0/1) ·
18 codeFailuresLastHour · 19 codeLockedOut (0/1)`

## Web

`/` status page and WiFi form · `/GetHostName` → `Cleotilde` (the NetworkInspector name lookup) ·
`GET /CleotildeServlet` JSON · `POST /CleotildeServlet` formName=ConfigSTA|ConfigAP

## Build & flash

Libraries: the sketchbook at `ProjectsSupport/Esp32ArduinoLib/libraries` (FastLED, Adafruit_SSD1306/GFX, Adafruit_INA219,
OneWire, Dallas, ArduinoJson, ESPAsyncWebServer, DigitalStablesEsp32Lib). Board: ESP32 Dev Module.
Flash for now over the direct USB link from the Cleotilde Pi with esptool (`/dev/ttyUSB0`).
Later: exported binary → factory flow (PaulaUploader/PaulaDeployer).
