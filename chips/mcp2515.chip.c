#include "wokwi-api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  pin_t cs_pin;
  pin_t int_pin;
  spi_dev_t spi;
  uart_dev_t uart;

  uint8_t regs[256];
  uint8_t spi_buf[1];
  uint8_t spi_cmd;
  uint8_t spi_addr;
  uint8_t spi_mask;
  uint32_t spi_idx;

  char rx_line[64];
  uint8_t rx_pos;
} chip_state_t;

static uint8_t hex_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return 0;
}

static void update_int_pin(chip_state_t *chip) {
  uint8_t active = chip->regs[0x2C] & chip->regs[0x2B];
  pin_write(chip->int_pin, active ? LOW : HIGH);
}

static void transmit_txb0_to_bus(chip_state_t *chip) {
  uint32_t id = ((uint32_t)chip->regs[0x31] << 3) | (chip->regs[0x32] >> 5);
  uint8_t dlc = chip->regs[0x35] & 0x0F;
  if (dlc > 8) dlc = 8;

  char slcan[40];
  int len = snprintf(slcan, sizeof(slcan), "t%03X%1X", (unsigned int)(id & 0x7FF), dlc);
  for (uint8_t i = 0; i < dlc; i++) {
    len += snprintf(slcan + len, sizeof(slcan) - len, "%02X", chip->regs[0x36 + i]);
  }
  slcan[len++] = '\r';
  uart_write(chip->uart, (uint8_t *)slcan, len);

  chip->regs[0x30] &= ~0x08;
  chip->regs[0x2C] |= 0x04;
  update_int_pin(chip);
}

static void parse_slcan_to_rxb0(chip_state_t *chip, const char *line) {
  if (line[0] != 't' || strlen(line) < 5) return;
  uint32_t id = (hex_val(line[1]) << 8) | (hex_val(line[2]) << 4) | hex_val(line[3]);
  uint8_t dlc = hex_val(line[4]);
  if (dlc > 8) dlc = 8;
  if (strlen(line) < (size_t)(5 + dlc * 2)) return;

  chip->regs[0x61] = (id >> 3) & 0xFF;
  chip->regs[0x62] = (id & 0x07) << 5;
  chip->regs[0x63] = 0;
  chip->regs[0x64] = 0;
  chip->regs[0x65] = dlc;
  for (uint8_t i = 0; i < dlc; i++) {
    chip->regs[0x66 + i] = (hex_val(line[5 + i * 2]) << 4) | hex_val(line[6 + i * 2]);
  }
  chip->regs[0x2C] |= 0x01;
  update_int_pin(chip);
}

static void on_uart_rx_data(void *user_data, uint8_t byte) {
  chip_state_t *chip = (chip_state_t *)user_data;
  if (byte == '\r' || byte == '\n') {
    if (chip->rx_pos > 0) {
      chip->rx_line[chip->rx_pos] = '\0';
      parse_slcan_to_rxb0(chip, chip->rx_line);
      chip->rx_pos = 0;
    }
  } else if (chip->rx_pos < sizeof(chip->rx_line) - 1) {
    chip->rx_line[chip->rx_pos++] = (char)byte;
  }
}

static uint8_t get_status_byte(chip_state_t *chip) {
  uint8_t st = 0;
  if (chip->regs[0x2C] & 0x01) st |= 0x01; // CANINTF.RX0IF
  if (chip->regs[0x2C] & 0x02) st |= 0x02; // CANINTF.RX1IF
  if (chip->regs[0x30] & 0x08) st |= 0x04; // TXB0CTRL.TXREQ
  if (chip->regs[0x2C] & 0x04) st |= 0x08; // CANINTF.TX0IF
  return st;
}

static void on_spi_done(void *user_data, uint8_t *buffer, uint32_t count) {
  chip_state_t *chip = (chip_state_t *)user_data;
  if (count == 0) return;

  uint8_t rx = buffer[0];
  uint8_t tx_next = 0x00;

  if (chip->spi_idx == 0) {
    chip->spi_cmd = rx;
    if (rx == 0xC0) { // INSTRUCTION_RESET
      memset(chip->regs, 0, sizeof(chip->regs));
      chip->regs[0x0F] = 0x80;
      chip->regs[0x0E] = 0x80;
      update_int_pin(chip);
    } else if (rx == 0xA0) { // INSTRUCTION_READ_STATUS
      tx_next = get_status_byte(chip);
    } else if (rx == 0xB0) { // INSTRUCTION_RX_STATUS
      tx_next = (chip->regs[0x2C] & 0x01) ? 0x40 : 0x00;
    } else if ((rx & 0xF8) == 0x80) { // INSTRUCTION_RTS
      if (rx & 0x01) transmit_txb0_to_bus(chip);
    } else if (rx == 0x90) { // INSTRUCTION_READ_RX0
      chip->spi_addr = 0x61;
      tx_next = chip->regs[chip->spi_addr];
    } else if (rx == 0x40) { // INSTRUCTION_LOAD_TX0
      chip->spi_addr = 0x31;
    }
  } else {
    uint8_t cmd = chip->spi_cmd;
    if (cmd == 0x03) { // INSTRUCTION_READ
      if (chip->spi_idx == 1) {
        chip->spi_addr = rx;
        tx_next = chip->regs[chip->spi_addr];
      } else {
        chip->spi_addr++;
        tx_next = chip->regs[chip->spi_addr];
      }
    } else if (cmd == 0x02) { // INSTRUCTION_WRITE
      if (chip->spi_idx == 1) {
        chip->spi_addr = rx;
      } else {
        uint8_t reg = chip->spi_addr++;
        chip->regs[reg] = rx;
        if (reg == 0x0F) chip->regs[0x0E] = (rx & 0xE0);
        if (reg == 0x30 && (rx & 0x08)) transmit_txb0_to_bus(chip);
        update_int_pin(chip);
      }
    } else if (cmd == 0x05) { // INSTRUCTION_BITMOD
      if (chip->spi_idx == 1) {
        chip->spi_addr = rx;
      } else if (chip->spi_idx == 2) {
        chip->spi_mask = rx;
      } else if (chip->spi_idx == 3) {
        uint8_t reg = chip->spi_addr;
        uint8_t mask = chip->spi_mask;
        chip->regs[reg] = (chip->regs[reg] & ~mask) | (rx & mask);
        if (reg == 0x0F) chip->regs[0x0E] = (chip->regs[0x0F] & 0xE0);
        if (reg == 0x30 && (chip->regs[0x30] & 0x08)) transmit_txb0_to_bus(chip);
        update_int_pin(chip);
      }
    } else if (cmd == 0xA0) {
      tx_next = get_status_byte(chip);
    } else if (cmd == 0xB0) {
      tx_next = (chip->regs[0x2C] & 0x01) ? 0x40 : 0x00;
    } else if (cmd == 0x40) {
      chip->regs[chip->spi_addr++] = rx;
    } else if (cmd == 0x90) {
      chip->spi_addr++;
      tx_next = chip->regs[chip->spi_addr];
      chip->regs[0x2C] &= ~0x01;
      update_int_pin(chip);
    }
  }

  chip->spi_idx++;
  if (pin_read(chip->cs_pin) == LOW) {
    chip->spi_buf[0] = tx_next;
    spi_start(chip->spi, chip->spi_buf, 1);
  }
}

static void on_cs_change(void *user_data, pin_t pin, uint32_t value) {
  chip_state_t *chip = (chip_state_t *)user_data;
  if (value == LOW) {
    chip->spi_idx = 0;
    chip->spi_cmd = 0;
    chip->spi_buf[0] = 0x00;
    spi_start(chip->spi, chip->spi_buf, 1);
  } else {
    spi_stop(chip->spi);
  }
}

void chip_init(void) {
  chip_state_t *chip = calloc(1, sizeof(chip_state_t));
  chip->cs_pin = pin_init("CS", INPUT_PULLUP);
  chip->int_pin = pin_init("INT", OUTPUT_HIGH);
  chip->regs[0x0F] = 0x80;
  chip->regs[0x0E] = 0x80;

  const pin_watch_config_t cs_watch = {
    .edge = BOTH,
    .pin_change = on_cs_change,
    .user_data = chip
  };
  pin_watch(chip->cs_pin, &cs_watch);

  const spi_config_t spi_cfg = {
    .sck = pin_init("SCK", INPUT),
    .mosi = pin_init("SI", INPUT),
    .miso = pin_init("SO", OUTPUT),
    .mode = 0,
    .done = on_spi_done,
    .user_data = chip
  };
  chip->spi = spi_init(&spi_cfg);

  const uart_config_t uart_cfg = {
    .tx = pin_init("CAN_TX", OUTPUT_HIGH),
    .rx = pin_init("CAN_RX", INPUT_PULLUP),
    .baud_rate = 115200,
    .rx_data = on_uart_rx_data,
    .user_data = chip
  };
  chip->uart = uart_init(&uart_cfg);
}