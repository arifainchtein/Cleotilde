// Cleotilde - the face of the Cleotilde Teleonome (network security / analyzer for the OpenWrt One router).
// Hardware: Wally 17 (ESP32) + Paula shield: 5 x WS2812 LEDs, 2.42" SSD1309 OLED, left/right slide switch,
// PCF8563 RTC (1 Hz on GPIO4), DS18B20 board temperature/serial number, INA219 on the power input.
// No LoRa. WiFi always on. The Pi (Teleonome "Cleotilde") drives the LEDs and OLED over serial (115200).
//
// Based on Annabelle.ino: same secret manager, WiFi manager base class and RTC handling, without LoRa,
// telepathons, weather or the DataManager queues. Everything Cleotilde-specific lives in this one file,
// including its WiFi manager subclass, because Wally has no firmware of its own.
//
// Design: OpenWrtOne/documents/05-teleonome-design.md (sections 5 and 10).
#include "Arduino.h"
#include <Wire.h>
#include <LittleFS.h>
#include <FastLED.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Adafruit_INA219.h>
#include "OneWire.h"
#include "DallasTemperature.h"
#include <PCF8563TimeManager.h>
#include <Esp32SecretManager.h>
#include <WifiManager.h>
#include <VitalSignsTracker.h>  // only for buildStamp()
#include <ArduinoJson.h>
#include <esp_system.h>

#define FIRMWARE_VERSION "Cleotilde-0.5"
#define DEVICE_TYPE_ID "Cleotilde"
#define DEFAULT_SSID "MainRouter24"  // open network, no password
#define DEFAULT_HOSTNAME "CleotildeESP32"  // the Pi is Cleotilde.local, so the ESP32 must not use that name

bool debug = false;
// YYMMDDhh of this build, so PaulaDeployer can tell whether the firmware label describes the running code.
const uint32_t FIRMWARE_BUILD = VitalSignsTracker::buildStamp(__DATE__, __TIME__);

// ---------------------------------------------------------------- pins (Wally 17 + Paula)
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
#define SCREEN_ADDRESS 0x3C
#define SLEEP_SWITCH_26 26
#define SWITCH_PIN_LEFT 32
#define SWITCH_PIN_RIGHT 33
#define LED_PIN 19
#define NUM_LEDS 5
#define RTC_BATT_VOLT 36
#define OP_MODE 34
#define RTC_CLK_OUT 4
#define ONE_WIRE_PIN 27

// RTC coin cell (CR1220) through the R41 (1M) / R46 (2M) divider, same as Langley/Daffodil.
#define RTC_BATT_DIVIDER_R1 1000000.0f
#define RTC_BATT_DIVIDER_R2 2000000.0f
#define RTC_BATT_ADC_VREF 3.3f

// INA219 on Wally's power input. Daffodil.ino has it at 0x45 with a 50 mOhm shunt (LVK12R050CER).
// Current is computed from the shunt voltage directly: getCurrent_mA() reads half on 50 mOhm with
// the library's default calibration. If 0x45 is empty the other INA219 addresses are tried.
#define INA219_DEFAULT_ADDR 0x45
#define INA219_SHUNT_OHMS 0.050f

// Pi silence: LED 5 goes yellow, then red, when the Pi stops talking.
#define PI_SILENT_WARN_SEC 120
#define PI_SILENT_ALARM_SEC 600
#define WIFI_RESTART_AFTER_SEC (15UL * 60UL)
#define RTC_SYNC_TOLERANCE_SEC 5

// Relay channels (modem, router) exist in the design (Cleotilde Build 1) but not on Wally 17 + Paula.
// The commands are implemented so the Pi side can be built now; they answer "no hardware".
#define RELAY_HARDWARE_PRESENT false

// VerifyUserCode (doorbell). A ring takes 1-2 min to reach the board (Zhinu -> SFTP -> Pi), longer than one
// 30 s TOTP step, so a code from any step in the last 3 min is accepted (one step ahead too, for clock skew).
// Each earlier step is accepted once. The current step can be used again: the Hypothalamus asks this board
// for a code (GetCommandCode) for each of its own CommandRequests and verifies it a moment later, often
// several in the same step. 5 wrong codes in an hour lock verification for an hour.
#define TOTP_STEP_SEC 30
#define VERIFY_STEPS_BACK 6  // 6 earlier steps + the current one = the last 3 minutes
#define VERIFY_STEPS_AHEAD 1
#define VERIFY_USED_STEPS 8
#define VERIFY_MAX_FAILURES 5
#define VERIFY_LOCKOUT_SEC 3600UL
#define VERIFY_REPEAT_SEC 15UL  // the Pi resends after a garbled answer, so a just-accepted code answers valid again

// ---------------------------------------------------------------- devices
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
CRGB leds[NUM_LEDS];
OneWire oneWire(ONE_WIRE_PIN);
DallasTemperature tempSensor(&oneWire);
PCF8563TimeManager timeManager(Serial);
Esp32SecretManager secretManager(timeManager);
Adafruit_INA219 *ina = nullptr;
uint8_t inaAddress = 0;

RTCInfoRecord currentTimerRecord;
String serialNumber = "";
String timezone = "AEST-10AEDT,M10.1.0,M4.1.0/3";
String resetReason = "";
float boardTemperature = NAN;
float rtcBatVolt = -1;
float inputVoltage = NAN, inputCurrentmA = NAN, inputPowermW = NAN;
bool switchPositionLeft = true;  // left = the Pi's pages, right = this board's own status page
bool rtcCheckedSinceBoot = false;
bool wifiStationWanted = false;
bool inPulse = false;

volatile bool clockTicked = false;
portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;

void IRAM_ATTR clockTick() {
  portENTER_CRITICAL_ISR(&mux);
  clockTicked = true;
  portEXIT_CRITICAL_ISR(&mux);
}

// ---------------------------------------------------------------- small helpers
// Field i of a '#'-separated command (0 = the command name).
String getValue(const String &data, char separator, int index) {
  int found = 0, start = 0;
  for (int i = 0; i <= (int)data.length(); i++) {
    if (i == (int)data.length() || data.charAt(i) == separator) {
      if (found == index) return data.substring(start, i);
      found++;
      start = i + 1;
    }
  }
  return "";
}

const char *resetReasonToString(esp_reset_reason_t reason) {
  switch (reason) {
    case ESP_RST_POWERON: return "PowerOn";
    case ESP_RST_EXT: return "External";
    case ESP_RST_SW: return "Software";
    case ESP_RST_PANIC: return "Panic";
    case ESP_RST_INT_WDT: return "IntWatchdog";
    case ESP_RST_TASK_WDT: return "TaskWatchdog";
    case ESP_RST_WDT: return "Watchdog";
    case ESP_RST_DEEPSLEEP: return "DeepSleep";
    case ESP_RST_BROWNOUT: return "Brownout";
    case ESP_RST_SDIO: return "SDIO";
    default: return "Unknown";
  }
}

// ---------------------------------------------------------------- LEDs
// Each LED has a colour and a blink flag, set by the Pi with SetLeds/SetLed. Colour letters:
// G green, Y yellow, R red, B blue, W white, O off. Lower case = blinking.
// Until the Pi sends anything, the board shows its own status: LED 1 WiFi, LED 5 heartbeat.
struct LedState {
  CRGB color;
  bool blink;
};
LedState ledState[NUM_LEDS];
bool piControlsLeds = false;
bool blinkPhase = false;
uint32_t lastPiCommandSec = 0;  // millis()/1000 of the last serial command from the Pi

CRGB colorFromLetter(char c) {
  switch (toupper(c)) {
    case 'G': return CRGB(0, 255, 0);
    case 'Y': return CRGB(255, 160, 0);
    case 'R': return CRGB(255, 0, 0);
    case 'B': return CRGB(0, 0, 255);
    case 'W': return CRGB(255, 255, 255);
    default: return CRGB::Black;
  }
}

void setLed(int i, char letter) {
  if (i < 0 || i >= NUM_LEDS) return;
  ledState[i].color = colorFromLetter(letter);
  ledState[i].blink = islower(letter);
}

void showLeds() {
  for (int i = 0; i < NUM_LEDS; i++) {
    leds[i] = (ledState[i].blink && !blinkPhase) ? CRGB::Black : ledState[i].color;
  }
  FastLED.show();
}

// Once a second: the board's own judgement layered over what the Pi asked for.
void updateStatusLeds() {
  blinkPhase = !blinkPhase;
  if (!piControlsLeds) {
    if (WiFi.status() == WL_CONNECTED) setLed(0, 'G');
    else if (WiFi.getMode() & WIFI_MODE_AP) setLed(0, 'B');
    else setLed(0, 'r');
    setLed(4, inPulse ? 'b' : 'g');  // heartbeat
  } else {
    // The Pi owns the LEDs, but if it goes quiet LED 5 (Teleonome) says so.
    uint32_t silent = millis() / 1000 - lastPiCommandSec;
    if (silent > PI_SILENT_ALARM_SEC) setLed(4, 'r');
    else if (silent > PI_SILENT_WARN_SEC) setLed(4, 'y');
  }
  showLeds();
}

// ---------------------------------------------------------------- OLED
// The Pi sends up to MAX_PI_PAGES pages (title + 6 lines). With the switch LEFT they rotate every
// PAGE_ROTATE_SEC; with the switch RIGHT the board shows its own status page.
#define MAX_PI_PAGES 6
#define PI_PAGE_LINES 6
#define PAGE_ROTATE_SEC 5
struct PiPage {
  String title;
  String lines[PI_PAGE_LINES];
  bool used;
};
PiPage piPages[MAX_PI_PAGES];
int currentPiPage = 0;
int pageSeconds = 0;

void centerText(const String &text, int y) {
  int16_t x1, y1;
  uint16_t w, h;
  display.getTextBounds(text, 0, y, &x1, &y1, &w, &h);
  display.setCursor((SCREEN_WIDTH - w) / 2, y);
  display.print(text);
}

void drawTitle(const String &title) {
  display.fillRect(0, 0, SCREEN_WIDTH, 9, SSD1306_WHITE);
  display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
  centerText(title, 1);
  display.setTextColor(SSD1306_WHITE);
}

void showPiPage(int p) {
  display.clearDisplay();
  display.setTextSize(1);
  drawTitle(piPages[p].title);
  for (int i = 0; i < PI_PAGE_LINES; i++) {
    display.setCursor(0, 11 + i * 9);
    display.print(piPages[p].lines[i]);
  }
  display.display();
}

void showWaitingForPi() {
  display.clearDisplay();
  display.setTextSize(2);
  centerText("Cleotilde", 10);
  display.setTextSize(1);
  centerText("waiting for the Pi", 36);
  centerText(WiFi.status() == WL_CONNECTED ? WiFi.localIP().toString() : String("no WiFi"), 50);
  display.display();
}

void showDevicePage() {
  char line[32];
  display.clearDisplay();
  display.setTextSize(1);
  snprintf(line, sizeof(line), "%02d:%02d:%02d %02d/%02d", currentTimerRecord.hour, currentTimerRecord.minute,
           currentTimerRecord.second, currentTimerRecord.date, currentTimerRecord.month);
  drawTitle(line);
  display.setCursor(0, 11);
  if (WiFi.status() == WL_CONNECTED) {
    display.printf("%s %ddBm", WiFi.localIP().toString().c_str(), (int)WiFi.RSSI());
  } else {
    display.print("WiFi down");
  }
  display.setCursor(0, 20);
  if (ina) display.printf("In %.2fV %.0fmA", inputVoltage, inputCurrentmA);
  else display.print("INA219 not found");
  display.setCursor(0, 29);
  display.printf("Board %.1fC RTC %.2fV", boardTemperature, rtcBatVolt);
  display.setCursor(0, 38);
  uint32_t up = millis() / 1000;
  display.printf("Up %lud %02lu:%02lu", up / 86400, (up / 3600) % 24, (up / 60) % 60);
  display.setCursor(0, 47);
  display.printf("Heap %uk Rst %s", ESP.getFreeHeap() / 1024, resetReason.c_str());
  display.setCursor(0, 56);
  display.print(FIRMWARE_VERSION);
  display.display();
}

void refreshDisplay() {
  if (!switchPositionLeft) {
    showDevicePage();
    return;
  }
  bool any = false;
  for (int i = 0; i < MAX_PI_PAGES; i++) any |= piPages[i].used;
  if (!any) {
    showWaitingForPi();
    return;
  }
  if (!piPages[currentPiPage].used || ++pageSeconds >= PAGE_ROTATE_SEC) {
    pageSeconds = 0;
    for (int n = 0; n < MAX_PI_PAGES; n++) {
      currentPiPage = (currentPiPage + 1) % MAX_PI_PAGES;
      if (piPages[currentPiPage].used) break;
    }
  }
  showPiPage(currentPiPage);
}

// ---------------------------------------------------------------- RTC
// Writes the PCF8563 time registers directly - see Annabelle.ino writeRtc() for why
// PCF8563TimeManager::setTime() is not used here.
void writeRtc(const struct tm &t) {
  auto bcd = [](int v) -> uint8_t { return (uint8_t)(((v / 10) << 4) | (v % 10)); };
  Wire.beginTransmission(0x51);
  Wire.write(0x02);
  Wire.write(bcd(t.tm_sec));
  Wire.write(bcd(t.tm_min));
  Wire.write(bcd(t.tm_hour));
  Wire.write(bcd(t.tm_mday));
  Wire.write(bcd(t.tm_wday));
  Wire.write(bcd(t.tm_mon + 1));
  Wire.write(bcd(t.tm_year - 100));
  Wire.endTransmission();
}

// The RTC keeps local time; this is the same moment as a Unix (UTC) epoch.
time_t rtcUtcEpoch() {
  setenv("TZ", timezone.c_str(), 1);  // WifiManager's connect task replaces TZ with a fixed offset
  tzset();
  struct tm rtc = {};
  rtc.tm_year = currentTimerRecord.year - 1900;
  rtc.tm_mon = currentTimerRecord.month - 1;
  rtc.tm_mday = currentTimerRecord.date;
  rtc.tm_hour = currentTimerRecord.hour;
  rtc.tm_min = currentTimerRecord.minute;
  rtc.tm_sec = currentTimerRecord.second;
  rtc.tm_isdst = -1;
  return mktime(&rtc);
}

// RTC <- internet time when they differ by more than RTC_SYNC_TOLERANCE_SEC (Annabelle's logic).
void syncRtcFromNtp() {
  setenv("TZ", timezone.c_str(), 1);
  tzset();
  struct tm ntp;
  if (!getLocalTime(&ntp, 0)) return;
  rtcCheckedSinceBoot = true;
  time_t ntpEpoch = time(nullptr);
  long diff = (long)(ntpEpoch - rtcUtcEpoch());
  if (labs(diff) <= RTC_SYNC_TOLERANCE_SEC) return;
  writeRtc(ntp);
  currentTimerRecord = timeManager.now();
  if (debug) Serial.printf("clock corrected by %ld s from NTP\n", diff);
}

// ---------------------------------------------------------------- sensors
void readRtcBattery() {
  float total = 0;
  const uint8_t samples = 20;
  for (int i = 0; i < samples; i++) {
    total += analogRead(RTC_BATT_VOLT);
    delay(2);
  }
  float average = total / samples;
  if (average >= 4090) {
    rtcBatVolt = -1;  // ADC saturated: floating pin or divider not fitted
  } else {
    float voltage = (average / 4095.0f) * RTC_BATT_ADC_VREF;
    rtcBatVolt = (voltage * (RTC_BATT_DIVIDER_R1 + RTC_BATT_DIVIDER_R2)) / RTC_BATT_DIVIDER_R2;
  }
}

bool i2cPresent(uint8_t address) {
  Wire.beginTransmission(address);
  return Wire.endTransmission() == 0;
}

void findIna219() {
  uint8_t candidates[] = { INA219_DEFAULT_ADDR, 0x40, 0x41, 0x44, 0x42, 0x43, 0x46, 0x47 };
  for (uint8_t a : candidates) {
    if (!i2cPresent(a)) continue;
    Adafruit_INA219 *candidate = new Adafruit_INA219(a);
    if (candidate->begin()) {
      ina = candidate;
      inaAddress = a;
      return;
    }
    delete candidate;
  }
}

void readPower() {
  if (!ina) return;
  inputVoltage = ina->getBusVoltage_V() + ina->getShuntVoltage_mV() / 1000.0f;  // supply side of the shunt
  inputCurrentmA = ina->getShuntVoltage_mV() / INA219_SHUNT_OHMS;
  inputPowermW = inputVoltage * inputCurrentmA;
}

// DS18B20: conversion started at second 15, read at second 17, so loop() never blocks ~750 ms.
void tickBoardTemperature(uint8_t second) {
  if (second == 15) {
    tempSensor.setWaitForConversion(false);
    tempSensor.requestTemperatures();
  } else if (second == 17) {
    float t = tempSensor.getTempCByIndex(0);
    boardTemperature = (t <= -127) ? NAN : t;
  }
}

// ---------------------------------------------------------------- WiFi manager
// Same pattern as LangleyWifiManager: station or AP mode from the secret manager, a small web page,
// /GetHostName for the NetworkInspector name lookup, and the config forms. The page is inline so the
// sketch needs no www partition.
class CleotildeWifiManager : public WifiManager {
public:
  CleotildeWifiManager(HardwareSerial &serial, FS &fs, PCF8563TimeManager &t, Esp32SecretManager &e)
    : WifiManager(serial, fs, t, e) {}

  void start() {
    ssid = secretManager.getSSID();
    password = secretManager.getWifiPassword();
    soft_ap_ssid = secretManager.getSoftAPSSID();
    soft_ap_password = secretManager.getSoftAPPASS();
    hostname = secretManager.getHostName();
    stationmode = secretManager.getStationMode();
    ssids = scanNetworks();
    WiFi.mode(WIFI_MODE_NULL);  // so the hostname is applied - arduino-esp32 issue 6700
    if (stationmode && ssid != "") connectSTA();
    else connectAP();

    asyncWebServer.on("/", HTTP_GET, [this](AsyncWebServerRequest *request) {
      request->send(200, "text/html", page());
    });
    asyncWebServer.on("/GetHostName", HTTP_GET, [this](AsyncWebServerRequest *request) {
      request->send(200, "text/plain", DEVICE_TYPE_ID);
    });
    asyncWebServer.on("/CleotildeServlet", HTTP_GET, [this](AsyncWebServerRequest *request) {
      AsyncResponseStream *response = request->beginResponseStream("application/json");
      DynamicJsonDocument json(2048);
      generateWebData(json, serialNumber);
      serializeJson(json, *response);
      request->send(response);
    });
    asyncWebServer.on("/CleotildeServlet", HTTP_POST, [this](AsyncWebServerRequest *request) {
      String formName = param(request, "formName");
      if (formName == "ConfigSTA") {
        if (configWifiSTA(param(request, "ssid"), param(request, "pass"), param(request, "host"))) {
          request->send(200, "text/plain", "Station mode saved, restarting");
          delay(500);
          ESP.restart();
        } else {
          request->send(500, "text/plain", "Could not join that network");
        }
      } else if (formName == "ConfigAP") {
        if (configWifiAP(param(request, "apaddress"), param(request, "pass"), param(request, "host"))) {
          request->send(200, "text/plain", "Access point mode saved, restarting");
          delay(500);
          ESP.restart();
        } else {
          request->send(500, "text/plain", "Could not start the access point");
        }
      } else {
        request->send(400, "text/plain", "Unknown formName");
      }
    });
    asyncWebServer.onNotFound([](AsyncWebServerRequest *request) {
      request->send(404, "text/plain", "Not found");
    });
    asyncWebServer.begin();
  }

  void generateWebData(DynamicJsonDocument &json, String sentBy) {
    json["deviceTypeId"] = DEVICE_TYPE_ID;
    json["firmware"] = FIRMWARE_VERSION;
    json["serialnumber"] = serialNumber;
    json["sentBy"] = sentBy;
    json["hostname"] = hostname;
    json["stationmode"] = stationmode;
    json["ssid"] = ssid;
    json["ipAddress"] = WiFi.localIP().toString();
    json["apAddress"] = apAddress;
    json["rssi"] = WiFi.RSSI();
    json["internetAvailable"] = internetAvailable;
    json["inputVoltage"] = inputVoltage;
    json["inputCurrentmA"] = inputCurrentmA;
    json["inputPowermW"] = inputPowermW;
    json["boardTemperature"] = boardTemperature;
    json["rtcBatVolt"] = rtcBatVolt;
    json["uptimeSec"] = millis() / 1000;
    json["freeHeap"] = ESP.getFreeHeap();
    json["resetReason"] = resetReason;
    json["relayHardware"] = RELAY_HARDWARE_PRESENT;
  }

  int uploadDataToDigitalStables() {
    return -1;  // Cleotilde reports to its Pi, not to devices.digitalstables.com
  }

private:
  static String param(AsyncWebServerRequest *request, const char *name) {
    const AsyncWebParameter *p = request->getParam(name, true);
    return p ? p->value() : String();
  }

  String page() {
    String s = F("<!doctype html><html><head><meta name=viewport content='width=device-width,initial-scale=1'>"
                 "<title>Cleotilde</title><style>body{font-family:sans-serif;margin:16px;max-width:480px}"
                 "td{padding:2px 8px}input{width:100%;padding:6px;margin:4px 0}</style></head><body>"
                 "<h2>Cleotilde</h2><table>");
    s += "<tr><td>Firmware</td><td>" FIRMWARE_VERSION "</td></tr>";
    s += "<tr><td>Serial</td><td>" + serialNumber + "</td></tr>";
    s += "<tr><td>WiFi</td><td>" + ssid + " " + WiFi.localIP().toString() + " " + String(WiFi.RSSI()) + " dBm</td></tr>";
    s += "<tr><td>Input</td><td>" + String(inputVoltage, 2) + " V " + String(inputCurrentmA, 0) + " mA</td></tr>";
    s += "<tr><td>Board</td><td>" + String(boardTemperature, 1) + " C, RTC cell " + String(rtcBatVolt, 2) + " V</td></tr>";
    s += "<tr><td>Uptime</td><td>" + String(millis() / 1000) + " s, reset: " + resetReason + "</td></tr>";
    s += F("</table><h3>Join a network</h3><form method=post action=/CleotildeServlet>"
           "<input type=hidden name=formName value=ConfigSTA>"
           "<input name=ssid placeholder=SSID><input name=pass placeholder='Password (blank if open)'>"
           "<input name=host placeholder=Hostname value='" DEFAULT_HOSTNAME "'><input type=submit value=Save></form>"
           "</body></html>");
    return s;
  }
};

CleotildeWifiManager wifiManager(Serial, LittleFS, timeManager, secretManager);

// After a router outage, reconnect every minute; restart after WIFI_RESTART_AFTER_SEC without WiFi
// (Annabelle's watchdog, added after it stayed off the house WiFi until reset by hand).
void wifiWatchdogTick() {
  static uint32_t downSec = 0;
  if (!wifiStationWanted) return;
  if (WiFi.status() == WL_CONNECTED) {
    downSec = 0;
    return;
  }
  downSec++;
  if (downSec % 60 == 0) WiFi.reconnect();
  if (downSec >= WIFI_RESTART_AFTER_SEC) ESP.restart();
}

// ---------------------------------------------------------------- serial protocol (Pi <-> Cleotilde)
// GetSensorData answers one '#'-separated line, positions fixed (append only, never reorder):
//  0 deviceTypeId  1 serialNumber  2 secondsTime  3 inputVoltage  4 inputCurrentmA  5 inputPowermW
//  6 boardTemperature  7 rtcBatVolt  8 wifiRssi  9 ipAddress  10 uptimeSec  11 freeHeap  12 minFreeHeap
//  13 switchPosition (L/R)  14 ina219Address (0 = none)  15 resetReason  16 firmware  17 relayHardware (0/1)
//  18 codeFailuresLastHour  19 codeLockedOut (0/1)
void sendSensorData() {
  long secondsTime = timeManager.getCurrentTimeInSeconds(currentTimerRecord);
  Serial.print(DEVICE_TYPE_ID); Serial.print('#');
  Serial.print(serialNumber); Serial.print('#');
  Serial.print(secondsTime); Serial.print('#');
  Serial.print(inputVoltage, 3); Serial.print('#');
  Serial.print(inputCurrentmA, 1); Serial.print('#');
  Serial.print(inputPowermW, 0); Serial.print('#');
  Serial.print(boardTemperature, 2); Serial.print('#');
  Serial.print(rtcBatVolt, 2); Serial.print('#');
  Serial.print(WiFi.status() == WL_CONNECTED ? WiFi.RSSI() : 0); Serial.print('#');
  Serial.print(WiFi.localIP().toString()); Serial.print('#');
  Serial.print(millis() / 1000); Serial.print('#');
  Serial.print(ESP.getFreeHeap()); Serial.print('#');
  Serial.print(ESP.getMinFreeHeap()); Serial.print('#');
  Serial.print(switchPositionLeft ? 'L' : 'R'); Serial.print('#');
  Serial.print(inaAddress); Serial.print('#');
  Serial.print(resetReason); Serial.print('#');
  Serial.print(FIRMWARE_VERSION); Serial.print('#');
  Serial.print(RELAY_HARDWARE_PRESENT ? 1 : 0); Serial.print('#');
  Serial.print(codeFailuresLastHour()); Serial.print('#');
  Serial.println(codeLockedOut() ? 1 : 0);
}

// ---------------------------------------------------------------- VerifyUserCode (doorbell)
long usedSteps[VERIFY_USED_STEPS];  // TOTP steps already accepted, oldest overwritten first
int usedStepPos = 0;
unsigned long failureSec[VERIFY_MAX_FAILURES];  // millis()/1000 of the last wrong codes, 0 = empty
int failurePos = 0;
long lastAcceptedCode = -1;
unsigned long lastAcceptedSec = 0;

int codeFailuresLastHour() {
  unsigned long now = millis() / 1000;
  int n = 0;
  for (int i = 0; i < VERIFY_MAX_FAILURES; i++) {
    if (failureSec[i] > 0 && now - failureSec[i] < VERIFY_LOCKOUT_SEC) n++;
  }
  return n;
}

// Locked while the last 5 wrong codes all fall within an hour; it unlocks an hour after the oldest of them
// drops out of that hour, i.e. at most an hour after the 5th.
bool codeLockedOut() {
  return codeFailuresLastHour() >= VERIFY_MAX_FAILURES;
}

bool stepUsed(long step) {
  for (int i = 0; i < VERIFY_USED_STEPS; i++) {
    if (usedSteps[i] == step) return true;
  }
  return false;
}

bool verifyUserCode(long userCode) {
  unsigned long nowSec = millis() / 1000;
  if (userCode == lastAcceptedCode && nowSec - lastAcceptedSec < VERIFY_REPEAT_SEC) return true;
  if (codeLockedOut()) return false;
  long currentStep = (long)rtcUtcEpoch() / TOTP_STEP_SEC;
  for (long step = currentStep - VERIFY_STEPS_BACK; step <= currentStep + VERIFY_STEPS_AHEAD; step++) {
    bool current = step == currentStep;
    if (!current && stepUsed(step)) continue;
    if (secretManager.generateCodeAt(step * TOTP_STEP_SEC) == userCode) {
      if (!current) {
        usedSteps[usedStepPos] = step;
        usedStepPos = (usedStepPos + 1) % VERIFY_USED_STEPS;
      }
      lastAcceptedCode = userCode;
      lastAcceptedSec = nowSec;
      return true;
    }
  }
  failureSec[failurePos] = nowSec > 0 ? nowSec : 1;
  failurePos = (failurePos + 1) % VERIFY_MAX_FAILURES;
  return false;
}

void handleSerialCommand(String command) {
  command.trim();
  lastPiCommandSec = millis() / 1000;

  if (command.startsWith("Ping")) {
    Serial.println(F("Ok-Ping"));
  } else if (command.startsWith("debug")) {
    debug = getValue(command, '#', 1).toInt() > 0;
    Serial.println(F("Ok-debug"));
  } else if (command.startsWith("Start ") || command.startsWith("End ")) {
    // Teleonome life cycle events ("Start Synchronous Cycle", ...), acknowledged as Annabelle does
    Serial.print(F("Ok-"));
    Serial.println(command);
  } else if (command.startsWith("PulseStart")) {
    inPulse = true;
    Serial.println(F("Ok-PulseStart"));
  } else if (command.startsWith("PulseFinished")) {
    inPulse = false;
    Serial.println(F("Ok-PulseFinished"));
  } else if (command.startsWith("GetSensorData")) {
    sendSensorData();
  } else if (command.startsWith("SetLeds")) {
    // SetLeds#G#Y#r#O#G - one colour letter per LED, lower case blinks
    for (int i = 0; i < NUM_LEDS; i++) {
      String c = getValue(command, '#', i + 1);
      if (c.length() > 0) setLed(i, c.charAt(0));
    }
    piControlsLeds = true;
    showLeds();
    Serial.println(F("Ok-SetLeds"));
  } else if (command.startsWith("SetLed#")) {
    // SetLed#3#R  (LEDs numbered 1-5)
    setLed(getValue(command, '#', 1).toInt() - 1, getValue(command, '#', 2).charAt(0));
    piControlsLeds = true;
    showLeds();
    Serial.println(F("Ok-SetLed"));
  } else if (command.startsWith("ReleaseLeds")) {
    piControlsLeds = false;  // back to the board's own status display
    Serial.println(F("Ok-ReleaseLeds"));
  } else if (command.startsWith("Oled#")) {
    // Oled#page#title#line1#...#line6   (page 1-6; empty title clears the page)
    int p = getValue(command, '#', 1).toInt() - 1;
    if (p >= 0 && p < MAX_PI_PAGES) {
      piPages[p].title = getValue(command, '#', 2);
      piPages[p].used = piPages[p].title.length() > 0;
      for (int i = 0; i < PI_PAGE_LINES; i++) piPages[p].lines[i] = getValue(command, '#', i + 3);
      if (switchPositionLeft && p == currentPiPage) showPiPage(p);
      Serial.println(F("Ok-Oled"));
    } else {
      Serial.println(F("Failure-Oled page must be 1-6"));
    }
  } else if (command.startsWith("ClearOled")) {
    for (int i = 0; i < MAX_PI_PAGES; i++) piPages[i].used = false;
    refreshDisplay();
    Serial.println(F("Ok-ClearOled"));
  } else if (command.startsWith("Relay")) {
    // Relay#1#CYCLE#10 = channel 1 off for 10 s then on. Cleotilde Build 1 only.
    if (!RELAY_HARDWARE_PRESENT) {
      Serial.println(F("Failure-NoRelayHardware"));
    }
  } else if (command.startsWith("SetProductDefinition")) {
    // SetProductDefinition#<name>#<powerSource>#<battery>#<pcbs>#<firmware>  (as Daffodil; PaulaDeployer
    // reads it back with GetProductDefinition and resends it with the new firmware label after a deploy)
    secretManager.saveProductDefinition(getValue(command, '#', 1), getValue(command, '#', 2), getValue(command, '#', 3),
                                        getValue(command, '#', 4), getValue(command, '#', 5), FIRMWARE_BUILD);
    Serial.println(F("Ok-SetProductDefinition"));
  } else if (command.startsWith("GetProductDefinition")) {
    // Same fields and order as Daffodil's answer, which PaulaDeployer and the factory's Inspect parse.
    String pdName, pdPowerSource, pdBattery, pdPcbs, pdFirmware;
    secretManager.getProductDefinition(pdName, pdPowerSource, pdBattery, pdPcbs, pdFirmware);
    unsigned long now = timeManager.getCurrentTimeInSeconds(currentTimerRecord);
    unsigned long commissionDate = secretManager.getCommissionDate();
    if (commissionDate < 1704067200UL) {  // before 2024-01-01 = never set (or an RTC reset default)
      commissionDate = now;
      secretManager.setCommissionDate(commissionDate);
    }
    Serial.println("Ok-GetProductDefinition#" + pdName + "#" + pdPowerSource + "#" + pdBattery + "#" + pdPcbs + "#" + pdFirmware +
                   "#" + String(commissionDate) + "#" + secretManager.getSSID() + "#" + secretManager.getWifiPassword() +
                   "#" + secretManager.getSoftAPSSID() + "#" + secretManager.getSoftAPPASS() + "#" + secretManager.getHostName() +
                   "#" + (secretManager.getStationMode() ? "Station" : "AccessPoint") + "#" + String(now) +
                   "#" + secretManager.readDeviceName() + "#" + secretManager.readDeviceShortName() + "#" + serialNumber +
                   "#" + String(secretManager.getProductDefinitionBuild()) + "#" + String(FIRMWARE_BUILD));
  } else if (command.startsWith("GetSerialNumber")) {
    Serial.println(serialNumber);
    Serial.println(F("Ok-GetSerialNumber"));
  } else if (command.startsWith("GetFirmware")) {
    Serial.println(FIRMWARE_VERSION);
    Serial.println(F("Ok-GetFirmware"));
  } else if (command.startsWith("ConfigWifiSTA")) {
    // ConfigWifiSTA#ssid#password#hostname
    bool ok = wifiManager.configWifiSTA(getValue(command, '#', 1), getValue(command, '#', 2), getValue(command, '#', 3));
    wifiStationWanted = ok;
    Serial.println(ok ? F("Ok-ConfigWifiSTA") : F("Failure-ConfigWifiSTA"));
  } else if (command.startsWith("ConfigWifiAP")) {
    // ConfigWifiAP#soft_ap_ssid#soft_ap_password#hostname
    bool ok = wifiManager.configWifiAP(getValue(command, '#', 1), getValue(command, '#', 2), getValue(command, '#', 3));
    Serial.println(ok ? F("Ok-ConfigWifiAP") : F("Failure-ConfigWifiAP"));
  } else if (command.startsWith("GetIpAddress")) {
    Serial.println(wifiManager.getIpAddress());
    Serial.println(F("Ok-GetIpAddress"));
  } else if (command.startsWith("RestartWifi")) {
    wifiManager.restartWifi();
    Serial.println(F("Ok-RestartWifi"));
  } else if (command.startsWith("ScanNetworks")) {
    Serial.println(wifiManager.scanNetworks());
    Serial.println(F("Ok-ScanNetworks"));
  } else if (command.startsWith("GetOperationMode")) {
    Serial.println(digitalRead(OP_MODE) == LOW ? F("PGM") : F("RUN"));
  } else if (command.startsWith("SetTimeFromInternet")) {
    wifiManager.setTimeFromInternet();
    currentTimerRecord = timeManager.now();
    Serial.println(F("Ok-SetTimeFromInternet"));
  } else if (command.startsWith("SetTime")) {
    // SetTime#d#m#yy#dow#hh#mm#ss
    timeManager.setTime(command);
    currentTimerRecord = timeManager.now();
    Serial.println(F("Ok-SetTime"));
  } else if (command.startsWith("GetTime")) {
    timeManager.printTimeToSerial(currentTimerRecord);
  } else if (command.startsWith("GetCommandCode")) {
    // Standard TOTP on UTC time, the same codes as the framework's TOTP.java and a phone authenticator app
    // (the library's getTimeForCodeGeneration() is not UTC).
    long code = secretManager.generateCodeAt((long)rtcUtcEpoch());
    if (code < 0) {
      Serial.println(F("Failure-NoSecret"));
    } else {
      char buf[8];
      snprintf(buf, sizeof(buf), "%06ld", code);  // the TOTP library drops leading zeros
      Serial.println(buf);
    }
  } else if (command.startsWith("VerifyUserCode")) {
    // VerifyUserCode#123456 -> the exact strings the framework expects (COMMAND_REQUEST_VALID_CODE / INVALID_CODE)
    String codeInString = getValue(command, '#', 1);
    bool valid = codeInString.length() > 0 && verifyUserCode(codeInString.toInt());
    Serial.println(valid ? F("Ok-Valid Code") : F("Failure-Invalid Code"));
  } else if (command.startsWith("GetSecret")) {
    Serial.println(secretManager.readSecret());
    Serial.println(F("Ok-GetSecret"));
  } else if (command.startsWith("SetSecret")) {
    // SetSecret#BASE32#digits#period
    secretManager.saveSecret(getValue(command, '#', 1), getValue(command, '#', 2).toInt(), getValue(command, '#', 3).toInt());
    Serial.println(F("Ok-SetSecret"));
  } else if (command.startsWith("ResetInfo")) {
    Serial.println(resetReason);
    Serial.println(F("Ok-ResetInfo"));
  } else if (command.startsWith("Reboot")) {
    Serial.println(F("Ok-Reboot"));
    Serial.flush();
    delay(200);
    ESP.restart();
  } else if (command == "Flush") {
    while (Serial.read() >= 0)
      ;
    Serial.println(F("Ok-Flush"));
  } else if (command.length() > 0) {
    Serial.print(F("Failure-Unknown command "));
    Serial.println(command);
  }
  Serial.flush();
}

// ---------------------------------------------------------------- setup / loop
void setup() {
  Serial.begin(115200);
  Serial.setTimeout(100);  // the Pi writes each command in one go (see Annabelle.ino)
  Wire.begin();
  resetReason = resetReasonToString(esp_reset_reason());

  pinMode(SLEEP_SWITCH_26, OUTPUT);
  digitalWrite(SLEEP_SWITCH_26, HIGH);
  pinMode(SWITCH_PIN_LEFT, INPUT_PULLUP);
  pinMode(SWITCH_PIN_RIGHT, INPUT_PULLUP);
  pinMode(RTC_BATT_VOLT, INPUT);
  pinMode(OP_MODE, INPUT_PULLUP);

  FastLED.addLeds<WS2812, LED_PIN, GRB>(leds, NUM_LEDS);
  FastLED.setBrightness(40);
  // Power-on test: each LED in turn red, yellow, green, so a dead LED is obvious.
  const char test[] = { 'R', 'Y', 'G' };
  for (char c : test) {
    for (int i = 0; i < NUM_LEDS; i++) setLed(i, c);
    showLeds();
    delay(300);
  }
  for (int i = 0; i < NUM_LEDS; i++) setLed(i, 'O');
  showLeds();

  bool displayOk = display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS);
  if (displayOk) {
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);
    display.setTextSize(2);
    centerText("Cleotilde", 16);
    display.setTextSize(1);
    centerText(FIRMWARE_VERSION, 40);
    display.display();
  } else {
    setLed(1, 'r');  // no OLED: LED 2 blinks red, the rest still works
    showLeds();
  }

  if (!LittleFS.begin(true)) {
    LittleFS.format();
    LittleFS.begin(false);
  }

  setenv("TZ", timezone.c_str(), 1);
  tzset();

  tempSensor.begin();
  uint8_t address[8];
  if (tempSensor.getAddress(address, 0)) {
    for (uint8_t i = 0; i < 8; i++) {
      if (address[i] < 0x10) serialNumber += "0";
      serialNumber += String(address[i], HEX);
    }
  }

  findIna219();
  readPower();
  readRtcBattery();

  pinMode(RTC_CLK_OUT, INPUT_PULLUP);
  timeManager.start();
  timeManager.PCF8563osc1Hz();
  attachInterrupt(digitalPinToInterrupt(RTC_CLK_OUT), clockTick, RISING);
  currentTimerRecord = timeManager.now();

  // Factory default: a brand-new board joins the house network (open) as CleotildeESP32.
  if (secretManager.getSSID() == "") {
    secretManager.saveWifiParameters(DEFAULT_SSID, "", "Cleotilde", "", DEFAULT_HOSTNAME, true);
  }
  wifiManager.pingVerbose = false;  // its ping lines would land on the Pi's serial line
  wifiManager.setSerialNumber(serialNumber);
  wifiManager.setLora(false);
  wifiManager.start();
  wifiStationWanted = wifiManager.getStationMode() && wifiManager.getSSID() != "";
  configTzTime(timezone.c_str(), "pool.ntp.org", "time.google.com");

  updateStatusLeds();
  refreshDisplay();
}

void loop() {
  if (clockTicked) {
    portENTER_CRITICAL(&mux);
    clockTicked = false;
    portEXIT_CRITICAL(&mux);

    currentTimerRecord = timeManager.now();
    wifiManager.setCurrentTimerRecord(currentTimerRecord);
    wifiWatchdogTick();

    uint8_t second = currentTimerRecord.second;
    if (second == 30 && (!rtcCheckedSinceBoot || currentTimerRecord.minute == 7)) syncRtcFromNtp();
    tickBoardTemperature(second);
    readPower();
    if (second == 45) readRtcBattery();

    int left = digitalRead(SWITCH_PIN_LEFT);
    int right = digitalRead(SWITCH_PIN_RIGHT);
    if (left == LOW && right == HIGH) switchPositionLeft = true;
    else if (left == HIGH && right == LOW) switchPositionLeft = false;

    updateStatusLeds();
    refreshDisplay();
  }

  if (Serial.available() != 0) {
    handleSerialCommand(Serial.readString());
  }
}
