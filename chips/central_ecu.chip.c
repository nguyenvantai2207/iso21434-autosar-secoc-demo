#include "wokwi-api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// --- Pure C SHA-256 Implementation (100% compatible with rweather/Crypto on BCM) ---
typedef struct {
  uint8_t data[64];
  uint32_t datalen;
  uint64_t bitlen;
  uint32_t state[8];
} sha256_ctx_t;

static const uint32_t k256[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(a,b) (((a) >> (b)) | ((a) << (32 - (b))))

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[]) {
  uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
  for (i = 0, j = 0; i < 16; ++i, j += 4)
    m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) | ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
  for (; i < 64; ++i)
    m[i] = (ROTR(m[i-2], 17) ^ ROTR(m[i-2], 19) ^ (m[i-2] >> 10)) + m[i-7] + (ROTR(m[i-15], 7) ^ ROTR(m[i-15], 18) ^ (m[i-15] >> 3)) + m[i-16];

  a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
  e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

  for (i = 0; i < 64; ++i) {
    t1 = h + (ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25)) + ((e & f) ^ (~e & g)) + k256[i] + m[i];
    t2 = (ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
  ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx_t *ctx) {
  ctx->datalen = 0; ctx->bitlen = 0;
  ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85; ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c; ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t data[], size_t len) {
  for (size_t i = 0; i < len; ++i) {
    ctx->data[ctx->datalen++] = data[i];
    if (ctx->datalen == 64) {
      sha256_transform(ctx, ctx->data);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t hash[]) {
  uint32_t i = ctx->datalen;
  ctx->data[i++] = 0x80;
  if (i > 56) {
    while (i < 64) ctx->data[i++] = 0x00;
    sha256_transform(ctx, ctx->data);
    i = 0;
  }
  while (i < 56) ctx->data[i++] = 0x00;
  ctx->bitlen += ctx->datalen * 8;
  for (int j = 0; j < 8; ++j) ctx->data[63 - j] = (ctx->bitlen >> (j * 8)) & 0xFF;
  sha256_transform(ctx, ctx->data);
  for (i = 0; i < 4; ++i) {
    for (int j = 0; j < 8; ++j) hash[i + j * 4] = (ctx->state[j] >> (24 - i * 8)) & 0xFF;
  }
}

// --- Central ECU Logic ---
typedef struct {
  pin_t btn_unlock;
  pin_t btn_lock;
  pin_t sw_sec;
  uart_dev_t uart;
  uint16_t freshness_counter;
  uint64_t last_press_ns;
} central_state_t;

static const char SECRET_KEY[] = "ISO21434_SECOC_KEY";

static void compute_mac(uint8_t cmd, uint16_t counter, uint8_t out_mac[4]) {
  sha256_ctx_t ctx;
  uint8_t hash[32];
  sha256_init(&ctx);
  sha256_update(&ctx, (const uint8_t *)SECRET_KEY, strlen(SECRET_KEY));
  sha256_update(&ctx, &cmd, 1);
  uint8_t cnt_bytes[2] = { (uint8_t)(counter >> 8), (uint8_t)(counter & 0xFF) };
  sha256_update(&ctx, cnt_bytes, 2);
  sha256_final(&ctx, hash);
  memcpy(out_mac, hash, 4);
}

static void send_door_command(central_state_t *chip, uint8_t cmd) {
  bool is_secured = (pin_read(chip->sw_sec) == LOW);
  char slcan[32];

  if (!is_secured) {
    // MODE 1: UNSECURED (Raw CAN 1 byte: 0x01=Unlock, 0x02=Lock)
    int len = snprintf(slcan, sizeof(slcan), "t1201%02X\r", cmd);
    uart_write(chip->uart, (uint8_t *)slcan, len);
  } else {
    // MODE 2: ISO/SAE 21434 + AUTOSAR SecOC (8 bytes)
    chip->freshness_counter++;
    uint8_t mac[4];
    compute_mac(cmd, chip->freshness_counter, mac);
    int len = snprintf(slcan, sizeof(slcan), "t1208%02X%04X%02X%02X%02X%02X00\r",
                       cmd, chip->freshness_counter, mac[0], mac[1], mac[2], mac[3]);
    uart_write(chip->uart, (uint8_t *)slcan, len);
  }
}

static void on_btn_unlock(void *user_data, pin_t pin, uint32_t value) {
  central_state_t *chip = (central_state_t *)user_data;
  if (value == LOW) {
    uint64_t now = get_sim_nanos();
    if (now - chip->last_press_ns < 200000000ULL) return; // Debounce 200ms
    chip->last_press_ns = now;
    send_door_command(chip, 0x01);
  }
}

static void on_btn_lock(void *user_data, pin_t pin, uint32_t value) {
  central_state_t *chip = (central_state_t *)user_data;
  if (value == LOW) {
    uint64_t now = get_sim_nanos();
    if (now - chip->last_press_ns < 200000000ULL) return; // Debounce 200ms
    chip->last_press_ns = now;
    send_door_command(chip, 0x02);
  }
}

static void on_central_rx_data(void *user_data, uint8_t byte) {
  // Optional: Handle response frames from BCM if needed
  (void)user_data;
  (void)byte;
}

void chip_init(void) {
  central_state_t *chip = calloc(1, sizeof(central_state_t));
  chip->btn_unlock = pin_init("BTN_UNLOCK", INPUT_PULLUP);
  chip->btn_lock   = pin_init("BTN_LOCK", INPUT_PULLUP);
  chip->sw_sec     = pin_init("SW_SEC", INPUT_PULLUP);

  const pin_watch_config_t watch_unlock = { .edge = FALLING, .pin_change = on_btn_unlock, .user_data = chip };
  const pin_watch_config_t watch_lock   = { .edge = FALLING, .pin_change = on_btn_lock,   .user_data = chip };
  pin_watch(chip->btn_unlock, &watch_unlock);
  pin_watch(chip->btn_lock, &watch_lock);

const uart_config_t uart_cfg = {
    .tx = pin_init("CAN_TX", OUTPUT_HIGH),
    .rx = pin_init("CAN_RX", INPUT_PULLUP),
    .baud_rate = 115200,
    .rx_data = on_central_rx_data,
    .user_data = chip
  };
  chip->uart = uart_init(&uart_cfg);
}