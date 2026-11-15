#include <Arduino.h>
#include <SPI.h>
#include <mcp2515.h>
#include <SHA256.h>
#include <Servo.h>

#define PIN_LED_VALID   6
#define PIN_LED_ATTACK  7
#define PIN_SERVO_DOOR  9
#define PIN_MCP_CS      10

MCP2515 mcp2515(PIN_MCP_CS);
Servo doorServo;

const char SECRET_KEY[] = "ISO21434_SECOC_KEY";
uint16_t last_valid_counter = 0;
char serial_rx_buf[64];
uint8_t serial_rx_pos = 0;

static int8_t hex_to_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

void print_cando_header() {
  Serial.println(F("======================================================================"));
  Serial.println(F("  [Cando CAN Bus Analyzer & AUTOSAR SecOC/IdsM Monitor - 500 kbps]"));
  Serial.println(F("  Inject format: '120 01' or '120 01 00 01 8E 86 5F 48 00'"));
  Serial.println(F("======================================================================"));
  Serial.println(F("   Time(s)  | Ch   | Dir | CAN ID | Type | DLC | Data (Hex)"));
  Serial.println(F("------------+------+-----+--------+------+-----+----------------------"));
}

void print_cando_frame(const struct can_frame &frame, bool is_injected) {
  unsigned long ms = millis();
  unsigned long sec = ms / 1000;
  unsigned int rem = ms % 1000;

  char line[80];
  char data_hex[26];

  int dpos = 0;
  for (uint8_t i = 0; i < frame.can_dlc; i++) {
    dpos += snprintf(data_hex + dpos, sizeof(data_hex) - dpos, "%02X ", frame.data[i]);
  }
  if (dpos == 0) data_hex[0] = '\0';

  snprintf(line, sizeof(line), " %6lu.%03u | can0 | %s | 0x%04X | STD  | [%1u] | %s",
           sec, rem,
           is_injected ? "INJ" : "RX ",
           (unsigned int)(frame.can_id & 0x7FF),
           frame.can_dlc,
           data_hex);
  Serial.println(line);
}

void compute_mac(uint8_t cmd, uint16_t counter, uint8_t out_mac[4]) {
  SHA256 sha;
  uint8_t hash[32];
  sha.reset();
  sha.update(SECRET_KEY, strlen(SECRET_KEY));
  sha.update(&cmd, 1);
  uint8_t cnt_bytes[2] = { (uint8_t)(counter >> 8), (uint8_t)(counter & 0xFF) };
  sha.update(cnt_bytes, 2);
  sha.finalize(hash, sizeof(hash));
  memcpy(out_mac, hash, 4);
}

void execute_door_action(uint8_t cmd) {
  digitalWrite(PIN_LED_ATTACK, LOW);
  digitalWrite(PIN_LED_VALID, HIGH);
  if (cmd == 0x01) {
    doorServo.write(90); // Unlock door actuator
    Serial.println(F("  -> Action: UNLOCKED (Servo 90 deg)"));
  } else if (cmd == 0x02) {
    doorServo.write(0);  // Lock door actuator
    Serial.println(F("  -> Action: LOCKED (Servo 0 deg)"));
  }
  delay(400);
  digitalWrite(PIN_LED_VALID, LOW);
}

void trigger_attack_alert(const __FlashStringHelper* reason) {
  Serial.print(F("[IdsM SECURITY EVENT] "));
  Serial.println(reason);
  for (int i = 0; i < 4; i++) {
    digitalWrite(PIN_LED_ATTACK, HIGH);
    delay(150);
    digitalWrite(PIN_LED_ATTACK, LOW);
    delay(150);
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(PIN_LED_VALID, OUTPUT);
  pinMode(PIN_LED_ATTACK, OUTPUT);
  doorServo.attach(PIN_SERVO_DOOR);
  doorServo.write(0);

  mcp2515.reset();
  mcp2515.setBitrate(CAN_500KBPS, MCP_8MHZ);
  mcp2515.setNormalMode();
  print_cando_header();
}

void process_can_frame(const struct can_frame &frame, bool is_injected) {
  print_cando_frame(frame, is_injected);
  if (frame.can_id != 0x120) return;

  // 1. Unsecured Mode (DLC = 1)
  if (frame.can_dlc == 1 && (frame.data[0] == 0x01 || frame.data[0] == 0x02)) {
    Serial.print(F("   [BCM UNSECURED] Command Accepted!"));
    execute_door_action(frame.data[0]);
    return;
  }

  // 2. ISO/SAE 21434 + AUTOSAR SecOC Mode (DLC = 8)
  if (frame.can_dlc == 8 && (frame.data[0] == 0x01 || frame.data[0] == 0x02)) {
    uint16_t rx_counter = ((uint16_t)frame.data[1] << 8) | frame.data[2];

    // Verify Freshness Value (Anti-Replay Protection)
    if (rx_counter <= last_valid_counter) {
      Serial.print(F("   "));
      trigger_attack_alert(F("SECOC_FRESHNESS_FAIL (Replay Attack Blocked!)"));
      return;
    }

    // Verify Truncated MAC (Anti-Spoofing Protection)
    uint8_t expected_mac[4];
    compute_mac(frame.data[0], rx_counter, expected_mac);
    if (memcmp(&frame.data[3], expected_mac, 4) != 0) {
      Serial.print(F("   "));
      trigger_attack_alert(F("SECOC_MAC_VERIFICATION_FAIL (Spoofing Blocked!)"));
      return;
    }

    last_valid_counter = rx_counter;
    Serial.print(F("   [BCM SECOC OK] Counter="));
    Serial.print(rx_counter);
    execute_door_action(frame.data[0]);
  }
}

bool parse_injected_line(const char *str, struct can_frame &out) {
  while (*str == ' ') str++;
  if (*str == '\0') return false;

  // Format 1: Lawicel SLCAN (t120101 or t12080100018E865F4800)
  if (*str == 't' || *str == 'T') {
    if (strlen(str) < 5) return false;
    int8_t id2 = hex_to_nibble(str[1]);
    int8_t id1 = hex_to_nibble(str[2]);
    int8_t id0 = hex_to_nibble(str[3]);
    int8_t dlc = hex_to_nibble(str[4]);
    if (id2 < 0 || id1 < 0 || id0 < 0 || dlc < 0 || dlc > 8) return false;
    if (strlen(str) < (size_t)(5 + dlc * 2)) return false;

    out.can_id = ((uint16_t)id2 << 8) | ((uint16_t)id1 << 4) | id0;
    out.can_dlc = dlc;
    for (uint8_t i = 0; i < dlc; i++) {
      int8_t hi = hex_to_nibble(str[5 + i * 2]);
      int8_t lo = hex_to_nibble(str[6 + i * 2]);
      if (hi < 0 || lo < 0) return false;
      out.data[i] = (hi << 4) | lo;
    }
    return true;
  }

  // Format 2: Cando / candump style ("120#01 00..." or "0x120 01 00...")
  if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) str += 2;
  uint32_t id = 0;
  uint8_t id_digits = 0;
  while (hex_to_nibble(*str) >= 0) {
    id = (id << 4) | hex_to_nibble(*str++);
    id_digits++;
  }
  if (id_digits == 0) return false;
  out.can_id = id & 0x7FF;

  while (*str == ' ' || *str == '#' || *str == ':' || *str == '|') str++;
  // Skip optional [DLC] bracket if user pasted directly from table
  if (*str == '[') {
    while (*str && *str != ']') str++;
    if (*str == ']') str++;
    while (*str == ' ' || *str == '|') str++;
  }

  uint8_t dlc = 0;
  while (*str && dlc < 8) {
    while (*str == ' ' || *str == '.' || *str == '-') str++;
    if (*str == '\0' || *str == '|') break;
    int8_t hi = hex_to_nibble(*str++);
    if (hi < 0) break;
    int8_t lo = hex_to_nibble(*str);
    if (lo >= 0) {
      str++;
      out.data[dlc++] = (hi << 4) | lo;
    } else {
      out.data[dlc++] = hi;
    }
  }
  if (dlc == 0) return false;
  out.can_dlc = dlc;
  return true;
}

void poll_serial_injection() {
  while (Serial.available() > 0) {
    char c = (char)Serial.read();
    if (c == '\r' || c == '\n') {
      if (serial_rx_pos > 0) {
        serial_rx_buf[serial_rx_pos] = '\0';
        struct can_frame injected;
        if (parse_injected_line(serial_rx_buf, injected)) {
          process_can_frame(injected, true);
        }
        serial_rx_pos = 0;
      }
    } else if (serial_rx_pos < sizeof(serial_rx_buf) - 1) {
      serial_rx_buf[serial_rx_pos++] = c;
    }
  }
}

void loop() {
  struct can_frame frame;
  if (mcp2515.readMessage(&frame) == MCP2515::ERROR_OK) {
    process_can_frame(frame, false);
  }
  poll_serial_injection();
}