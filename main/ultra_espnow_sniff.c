/*
 * ultra_espnow_sniff - capture ESP-NOW frames with an ESP32 in promiscuous mode and stream
 *                  them out of the serial port as a pcap, for espnow-sniff to decode
 *
 * The point of doing this on an ESP32 rather than a USB WiFi adapter is that the radio
 * talks to the CPU over on-die DMA instead of a USB pipeline, so there is no host bus to
 * stall and lose a burst of frames in.
 *
 * No credentials and no network are involved: the radio never associates, it only listens,
 * and the capture leaves over the same UART used for flashing.
 *
 *   host $ stty -F /dev/ttyUSB0 921600 raw -echo
 *   host $ printf 'T%d\n' $(date +%s) > /dev/ttyUSB0     # optional, for absolute times
 *   host $ cat /dev/ttyUSB0 | espnow-sniff -r /dev/stdin
 *
 * The stream is a plain pcap with DLT_IEEE802_11_RADIOTAP. Boot chatter from the ROM
 * loader arrives at the wrong baud and lands in front of it, so the decoder resynchronises
 * on the pcap magic.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/ringbuf.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_timer.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "nvs_flash.h"
#include "driver/uart.h"

#if defined(SNIFF_COLLECTOR)
#include "esp_netif.h"
#include "esp_eth.h"
#include "esp_sntp.h"
#include "driver/gpio.h"
#include "ethernet_init.h"
#include "lwip/sockets.h"
#include "esp_ota_ops.h"
#include "esp_https_ota.h"
#include "esp_http_client.h"
#include <ctype.h>
#include <sys/time.h>
#endif

#include "mlcf.h"

#define UART_PORT       UART_NUM_0
#define UART_BAUD       921600
#define CHANNEL         6                   /* override with -DSNIFF_CHANNEL=n */
#define FRAME_MAX       320                 /* an ESP-NOW frame cannot exceed this */
#define RING_BYTES      (48 * 1024)
#define STATS_PERIOD_US (10 * 1000000LL)

/*
 * transport: without SNIFF_COLLECTOR the capture leaves over the UART, which is what a
 * bench unit on a USB cable wants. define it (and optionally SNIFF_PORT / SNIFF_NTP)
 * and the unit brings up ethernet instead and streams the same pcap to that collector,
 * which is what a permanently placed unit wants:
 *
 *   OPTS_='-DSNIFF_COLLECTOR=\"192.168.0.12\"' idf.py build
 *
 * no address is baked in here on purpose - this file carries no site data.
 */
#ifndef SNIFF_PORT
#define SNIFF_PORT      5555
#endif
#ifndef SNIFF_NTP
#define SNIFF_NTP       "pool.ntp.org"
#endif

#ifdef SNIFF_CHANNEL
#undef  CHANNEL
#define CHANNEL SNIFF_CHANNEL
#endif

typedef struct {
    int64_t  us;                            /* esp_timer, microseconds since boot */
    _i8   rssi;
    _u8  channel;
    _u8  rate;                          /* radiotap units, 500 kb/s */
    _u16 len;
} chdr_t;

static RingbufHandle_t  rb;
#if defined(SNIFF_COLLECTOR)
static int              sock = -1;
#endif
static volatile _u32 n_seen, n_dropped, n_offline;
/*
 * unconditional on purpose: SNIFF_OTA_URL can still be #undef'd further down (when SERNO is
 * missing), so anything guarded on it up here risks disagreeing with the code that uses it
 */
static volatile _u32 n_otaskip;         /* update checks skipped for want of a collector */
static volatile int  ota_kick;          /* a collector arrived: bring the next check forward */
static _u32 n_stale;                    /* backlog frames thrown away on (re)connect */

/* buildit stamps the running build into build_id.h; a hand build has none */
#if defined(SERNO)
#define SNIFF_FW    SERNO
#else
#define SNIFF_FW    "?"
#endif
static volatile int64_t epoch_us;      /* unix microseconds at boot, 0 until synced */

/*
 * wifi_phy_rate_t -> radiotap rate, in 500 kb/s units. only the 11b/g rates matter here;
 * anything else is reported as 0, which radiotap readers show as unknown
 */
static _u8
phy_rate(_u8 r)
{
    static const _u8 tab[16] = {
        2, 4, 11, 22, 0, 4, 11, 22,         /* 1M 2M 5.5M 11M   -  2Ms 5.5Ms 11Ms */
       96, 48, 24, 12, 108, 72, 36, 18      /* 48M 24M 12M 6M  54M 36M 18M 9M     */
    };

    return (r < 16) ? tab[r] : 0;
}

/*
 * promiscuous callback. this runs in the WiFi task and blocks it, so it does the least
 * possible: reject anything that is not ESP-NOW, then hand the frame to the ring buffer
 */
static void
sniff_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;
    const _u8 *f;
    _u8 *dst;
    chdr_t h;
    int len;

    if (type != WIFI_PKT_MGMT)
        return;

    f   = p->payload;
    len = (int)p->rx_ctrl.sig_len - 4;      /* sig_len counts the FCS, we do not want it */
    if (len < 32 || len > FRAME_MAX)
        return;
    if (f[0] != 0xd0)                       /* management, subtype action */
        return;
    if (f[24] != 0x7f ||                    /* category: vendor specific */
        f[25] != 0x18 || f[26] != 0xfe || f[27] != 0x34)
        return;                             /* Espressif OUI */

    n_seen++;

    h.us      = esp_timer_get_time();
    h.rssi    = p->rx_ctrl.rssi;
    h.channel = p->rx_ctrl.channel;
    h.rate    = phy_rate(p->rx_ctrl.rate);
    h.len     = (_u16)len;

    if (xRingbufferSendAcquire(rb, (void **)&dst, sizeof(h) + len, 0) != pdTRUE) {
        /*
         * a full ring means two very different things and only one of them is a fault.
         * with no collector attached the writer does not drain at all, so the ring is
         * expected to be full and the frame was never going anywhere: that is not a
         * loss worth alarming about. with a collector attached it means the link or
         * the writer genuinely could not keep up, which is the number to watch
         */
#if defined(SNIFF_COLLECTOR)
        if (sock < 0)
            n_offline++;
        else
#endif
            n_dropped++;
        return;
    }
    memcpy(dst, &h, sizeof(h));
    memcpy(dst + sizeof(h), f, len);
    xRingbufferSendComplete(rb, dst);
}

static void
out(const void *p, int n)
{
#if defined(SNIFF_COLLECTOR)
    const _u8 *q = (const _u8 *)p;
    int w;

    while (sock >= 0 && n > 0) {
        if ((w = send(sock, q, n, 0)) <= 0) {
            close(sock);
            sock = -1;                      /* the writer task reconnects */
            return;
        }
        q += w;
        n -= w;
    }
#else
    uart_write_bytes(UART_PORT, p, n);
#endif
}

#if defined(SNIFF_COLLECTOR)

/*
 * bring up ethernet. which PHY is chosen in sdkconfig, so one code path serves both the
 * LAN8720 boards and the SPI W5500 ones
 */
static void
eth_up(void)
{
    esp_netif_config_t ncfg = ESP_NETIF_DEFAULT_ETH();
    esp_eth_handle_t *handles;
    _u8 cnt = 0;

#if defined(CONFIG_EXAMPLE_ETH_PHY_LAN87XX)
    gpio_reset_pin(GPIO_NUM_16);            /* wt32-eth01: enable the 50MHz oscillator */
    gpio_set_direction(GPIO_NUM_16, GPIO_MODE_OUTPUT);
    gpio_set_level(GPIO_NUM_16, 1);
#endif
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(example_eth_init(&handles, &cnt));
    ESP_ERROR_CHECK(cnt == 1 ? ESP_OK : ESP_FAIL);
    ESP_ERROR_CHECK(esp_netif_attach(esp_netif_new(&ncfg), esp_eth_new_netif_glue(handles[0])));
    ESP_ERROR_CHECK(esp_eth_start(handles[0]));

    esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, SNIFF_NTP);
    esp_sntp_init();
}

/*
 * SNTP only has to get close. overlapping collectors are aligned exactly afterwards by
 * cross correlating the frames they both heard, which beats any clock protocol here
 */
static void
clock_sync(void)
{
    struct timeval tv;

    if (gettimeofday(&tv, 0) == 0 && tv.tv_sec > 1700000000)
        epoch_us = (int64_t)tv.tv_sec * 1000000LL + tv.tv_usec - esp_timer_get_time();
}

static int
collector_connect(void)
{
    struct sockaddr_in sa;
    struct timeval to;
    int s, one = 1;

    if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        return -1;
    to.tv_sec = 5; to.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &to, sizeof(to));
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(SNIFF_PORT);
    sa.sin_addr.s_addr = inet_addr(SNIFF_COLLECTOR);
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(s);
        return -1;
    }
    return s;
}

/*
 * OTA needs PROJECT / ENTITY / SERNO, which buildit generates into build_id.h. A plain
 * idf.py build has none of them, so say so plainly instead of failing on an unknown
 * identifier fifty lines further down
 */
#if defined(SNIFF_OTA_URL) && !defined(SERNO)
#warning SNIFF_OTA_URL is set but SERNO is not - build through buildit to get OTA
#undef SNIFF_OTA_URL
#endif

#if defined(SNIFF_OTA_URL)

/*
 * OTA over ethernet. buildit publishes each build to the firmware directory as
 * <PROJECT>-<ENTITY>-<SERNO>.bin and removes the entity's previous one, so the newest
 * build is found by listing that directory and taking the highest serial - the same
 * scheme mcom.h uses, without the regex.
 *
 * These units end up soldered in place, so a bad image must never need the iron back.
 * The bootloader rollback is armed (CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE) and a fresh
 * image only marks itself valid once it has actually reached the collector; anything
 * that cannot do that is reverted by the bootloader on the next boot.
 */

#define OTA_PERIOD_MS   (15 * 60 * 1000)
#define OTA_FIRST_MS    (60 * 1000)     /* a rebooted unit should not wait a quarter hour */
#define OTA_SLICE_MS    (5 * 1000)      /* granularity at which a kick is noticed */

/* the server log should say which device asked, not "ESP32 HTTP Client" */
#define _STR(x)     #x
#define _XSTR(x)    _STR(x)
#define DEVICE_FW   PROJECT "-" _XSTR(ENTITY) "-" SERNO
#define SERNO_          strtol(SERNO, 0, 16)

static volatile int ota_validated;

/*
 * pick the highest <hex> out of every "<prefix><hex>.bin" in the directory listing
 */
static _u32
ota_scan(const char *buf, const char *pfx, char *name, int nsz)
{
    const char *p = buf, *s;
    _u32 best = 0, v;
    int n = strlen(pfx), i;

    while ((p = strstr(p, pfx))) {
        s = p;
        p += n;
        for (v = 0, i = 0; isxdigit((unsigned char)p[i]); i++)
            v = v * 16 + (isdigit((unsigned char)p[i]) ? p[i] - '0'
                                                       : tolower((unsigned char)p[i]) - 'a' + 10);
        if (i && !strncmp(p + i, ".bin", 4) && v > best) {
            best = v;
            snprintf(name, nsz, "%.*s", (int)(p + i + 4 - s), s);
        }
    }
    return best;
}

static _u32
ota_latest(char *name, int nsz)
{
    esp_http_client_config_t cfg = {
        .url        = SNIFF_OTA_URL,
        .method     = HTTP_METHOD_GET,
        .user_agent = DEVICE_FW,
        .timeout_ms = 5000,
    };
    esp_http_client_handle_t c;
    char pfx[64];
    static char buf[8192];              /* one file per entity, the listing is small */
    int total = 0, r;
    _u32 best;

    snprintf(pfx, _SZ(pfx), "%s-%d-", PROJECT, ENTITY);

    if (!(c = esp_http_client_init(&cfg)))
        return 0;
    if (esp_http_client_open(c, 0) != ESP_OK) {
        esp_http_client_cleanup(c);
        return 0;
    }
    esp_http_client_fetch_headers(c);
    while (total < (int)_SZ(buf) - 1 &&
           (r = esp_http_client_read(c, buf + total, _SZ(buf) - 1 - total)) > 0)
        total += r;
    buf[total] = 0;
    esp_http_client_close(c);
    esp_http_client_cleanup(c);

    best = ota_scan(buf, pfx, name, nsz);
    return best;
}

static void
ota_task(void *arg)
{
    esp_http_client_config_t hc = { .timeout_ms = 20000, .keep_alive_enable = true,
                                    .user_agent = DEVICE_FW };
    esp_https_ota_config_t oc = { .http_config = &hc };
    char name[96], url[320];
    _u32 latest;
    int waited;

    vTaskDelay(pdMS_TO_TICKS(OTA_FIRST_MS));

    for (;;) {
        /*
         * the collector link is not just a nicety here, it is the interlock: a freshly
         * OTA'd image boots PENDING_VERIFY and only ota_mark_valid() cancels the rollback,
         * which runs when frames are demonstrably reaching the collector. update with no
         * collector attached and the new image could never prove itself, so the bootloader
         * would revert it at the next power cycle - a far more puzzling failure than simply
         * not updating. so skip, but COUNT the skip: the loop keeps its 15 minute phase
         * either way, which makes a run of skipped checks look exactly like a dead task in
         * the server log
         */
        if (sock < 0)
            n_otaskip++;
        else {
            *name = 0;
            latest = ota_latest(name, _SZ(name));
            if (latest > (_u32)SERNO_) {
                snprintf(url, _SZ(url), "%s%s", SNIFF_OTA_URL, name);
                hc.url = url;
                if (esp_https_ota(&oc) == ESP_OK)
                    esp_restart();      /* a good image reboots into the new slot */
            }
        }

        /*
         * any kick raised before now is already answered by the check just done - clear it,
         * or the connect that happens while a rebooted unit is still inside OTA_FIRST_MS
         * fires a second, pointless check one slice later
         */
        ota_kick = 0;

        /*
         * wait the period out in slices, so a collector that comes back mid window brings
         * the next check forward instead of leaving the device idle for up to another full
         * period after it is once again updatable
         */
        for (waited = 0; waited < OTA_PERIOD_MS; waited += OTA_SLICE_MS) {
            vTaskDelay(pdMS_TO_TICKS(OTA_SLICE_MS));
            if (ota_kick) {
                ota_kick = 0;
                break;
            }
        }
    }
}

/*
 * called once the capture has demonstrably reached the collector. until this runs, a
 * freshly flashed image is PENDING_VERIFY and the bootloader will revert to the
 * previous one, which is the only recovery a soldered in board has
 */
static void
ota_mark_valid(void)
{
    const esp_partition_t *run = esp_ota_get_running_partition();
    esp_ota_img_states_t st;

    if (ota_validated)
        return;
    ota_validated = 1;
    if (esp_ota_get_state_partition(run, &st) == ESP_OK && st == ESP_OTA_IMG_PENDING_VERIFY)
        esp_ota_mark_app_valid_cancel_rollback();
}

#endif  /* SNIFF_OTA_URL */

#endif  /* SNIFF_COLLECTOR */
static void
le32(_u8 *b, _u32 v)
{
    b[0] = v; b[1] = v >> 8; b[2] = v >> 16; b[3] = v >> 24;
}

static void
pcap_header(void)
{
    _u8 g[24];

    le32(g +  0, 0xa1b2c3d4);               /* magic, little endian host, microseconds */
    g[4] = 2; g[5] = 0; g[6] = 4; g[7] = 0; /* version 2.4 */
    le32(g +  8, 0);                        /* thiszone */
    le32(g + 12, 0);                        /* sigfigs  */
    le32(g + 16, 65535);                    /* snaplen  */
    le32(g + 20, 127);                      /* DLT_IEEE802_11_RADIOTAP */
    out(g, sizeof(g));
}

/*
 * one pcap record: record header, a 15 byte radiotap carrying Flags, Rate, Channel and
 * dBm antenna signal, then the 802.11 frame with the FCS already removed
 */
static void
pcap_frame(const chdr_t *h, const _u8 *f)
{
    _u8 rec[16], rt[15];
    int64_t us = h->us + epoch_us;
    _u16 freq, cflags;

    le32(rec + 0, (_u32)(us / 1000000));
    le32(rec + 4, (_u32)(us % 1000000));
    le32(rec + 8,  sizeof(rt) + h->len);
    le32(rec + 12, sizeof(rt) + h->len);

    freq   = (h->channel == 14) ? 2484 : 2407 + 5 * h->channel;
    cflags = (h->rate && h->rate <= 22) ? 0x00a0 : 0x00c0;      /* 2GHz, CCK or OFDM */

    rt[0] = 0; rt[1] = 0;                   /* it_version, it_pad */
    rt[2] = sizeof(rt); rt[3] = 0;          /* it_len */
    le32(rt + 4, 0x0000002e);               /* Flags | Rate | Channel | dBm antsignal */
    rt[8]  = 0x00;                          /* Flags: no FCS at end */
    rt[9]  = h->rate;
    rt[10] = freq; rt[11] = freq >> 8;
    rt[12] = cflags; rt[13] = cflags >> 8;
    rt[14] = (_u8)h->rssi;

    out(rec, sizeof(rec));
    out(rt,  sizeof(rt));
    out(f,   h->len);
}

/*
 * counters have to reach the host somehow, and the serial line carries nothing but pcap.
 * so report them as a synthetic ESP-NOW frame from a locally administered address: the
 * decoder on the other end renders it as an ordinary line with a readable payload
 */
static void
emit_stats(void)
{
    _u8 me[6] = { 0x02, 0, 0, 0, 0, 0xff };
    _u8 mac[6];
    _u8 f[224];                         /* 39 bytes of framing, then txt */
    char txt[128];                      /* must not truncate: the counters are the point */
    chdr_t h;
    int n = 0, plen;

    /* tag the stats with our own radio, so several collectors stay distinguishable */
    if (esp_wifi_get_mac(WIFI_IF_STA, mac) == ESP_OK) {
        me[3] = mac[3]; me[4] = mac[4]; me[5] = mac[5];
    }
    plen = snprintf(txt, _SZ(txt),
                    "sniffer %02x:%02x:%02x fw=%s rx=%lu dropped=%lu stale=%lu offline=%lu"
                    " otaskip=%lu",
                    me[3], me[4], me[5], SNIFF_FW,
                    (unsigned long)n_seen, (unsigned long)n_dropped,
                    (unsigned long)n_stale, (unsigned long)n_offline,
                    (unsigned long)n_otaskip) + 1;

    f[n++] = 0xd0; f[n++] = 0x00;                   /* action */
    f[n++] = 0x00; f[n++] = 0x00;                   /* duration */
    memcpy(f + n, me, 6); n += 6;                   /* DA */
    memcpy(f + n, me, 6); n += 6;                   /* SA */
    memset(f + n, 0xff, 6); n += 6;                 /* BSSID */
    f[n++] = 0x00; f[n++] = 0x00;                   /* sequence control */
    f[n++] = 0x7f;
    f[n++] = 0x18; f[n++] = 0xfe; f[n++] = 0x34;
    le32(f + n, esp_random()); n += 4;
    f[n++] = 0xdd; f[n++] = (_u8)(5 + plen);
    f[n++] = 0x18; f[n++] = 0xfe; f[n++] = 0x34;
    f[n++] = 0x04; f[n++] = 0x01;
    memcpy(f + n, txt, plen); n += plen;

    h.us = esp_timer_get_time();
    h.rssi = 0; h.channel = CHANNEL; h.rate = 2; h.len = n;
    pcap_frame(&h, f);
}

#if defined(SNIFF_COLLECTOR)
/*
 * while no collector is connected the writer does not drain, so the ring fills with the
 * OLDEST frames after the disconnect and every later frame is refused (and counted as
 * dropped). handing that snapshot to a freshly connected collector would inject frames
 * that are minutes to an hour old and that no other collector reports -- which is exactly
 * the input the dedup and coverage arithmetic must not get. so throw it away and start live
 */
static _u32
ring_discard(void)
{
    _u32 n = 0;
    size_t sz;
    void *item;

    while ((item = xRingbufferReceive(rb, &sz, 0)) != NULL) {
        vRingbufferReturnItem(rb, item);
        n++;
    }
    return n;
}
#endif

static void
writer_task(void *arg)
{
    int64_t next_stats = esp_timer_get_time() + STATS_PERIOD_US;
    _u8 *item;
    size_t sz;
    chdr_t h;

#if !defined(SNIFF_COLLECTOR)
    pcap_header();
#endif

    for (;;) {
#if defined(SNIFF_COLLECTOR)
        if (sock < 0) {                     /* keep trying until a collector is there */
            if ((sock = collector_connect()) < 0) {
                vTaskDelay(pdMS_TO_TICKS(2000));
                continue;                   /* frames pile up and are counted as dropped */
            }
            clock_sync();
            n_stale += ring_discard();      /* the backlog is old news, not live traffic */
            pcap_header();                  /* the new reader needs one immediately */
            ota_kick = 1;                   /* updatable again - do not sit out the period */
        }
#endif
        item = (_u8 *)xRingbufferReceive(rb, &sz, pdMS_TO_TICKS(500));
        if (item) {
            if (sz >= sizeof(h)) {
                memcpy(&h, item, sizeof(h));
                if (sz == sizeof(h) + h.len)
                    pcap_frame(&h, item + sizeof(h));
            }
            vRingbufferReturnItem(rb, item);
        }
        if (esp_timer_get_time() >= next_stats) {
#if defined(SNIFF_COLLECTOR)
            clock_sync();                   /* follow SNTP as it settles */
#endif
            pcap_header();          /* repeated, so a reader may join mid stream */
            emit_stats();
#if defined(SNIFF_COLLECTOR) && defined(SNIFF_OTA_URL)
            ota_mark_valid();               /* reaching the collector proves this image */
#endif
            next_stats = esp_timer_get_time() + STATS_PERIOD_US;   /* do not catch up */
        }
    }
}

/*
 * the board has no clock. accept "T<unix seconds>" on the same line at any time, so
 * the capture can carry absolute timestamps and be lined up against another sniffer.
 * without it the times simply start at the epoch
 */
#if !defined(SNIFF_COLLECTOR)
static void
time_task(void *arg)
{
    _u8 b[64];
    int n, i;

    for (;;) {
        n = uart_read_bytes(UART_PORT, b, _SZ(b) - 1, pdMS_TO_TICKS(1000));
        if (n <= 0)
            continue;
        b[n] = 0;
        for (i = 0; i < n; i++)
            if (b[i] == 0x54)                   /* T */
                epoch_us = strtoll((char *)&b[i + 1], 0, 10) * 1000000LL
                           - esp_timer_get_time();   /* h->us is uptime, not wall clock */
    }
}
#endif

/*
 * nvs_flash_init() fails with NO_FREE_PAGES whenever the nvs partition is new or was
 * resized - which is exactly what happens the first time a board boots a changed
 * partition table. Ignoring that return leaves esp_wifi_init() aborting on
 * ESP_ERR_NVS_NOT_INITIALIZED, i.e. a boot loop, so erase and retry.
 */
static void
nvs_init(void)
{
    esp_err_t r = nvs_flash_init();

    if (r == ESP_ERR_NVS_NO_FREE_PAGES || r == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        r = nvs_flash_init();
    }
    ESP_ERROR_CHECK(r);
}

void
app_main(void)
{
#if !defined(SNIFF_COLLECTOR)
    uart_config_t uc = {
        .baud_rate  = UART_BAUD,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
#endif
    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT();
    wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };

#if defined(SNIFF_COLLECTOR)
    nvs_init();
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    eth_up();                               /* link, DHCP and SNTP come up on their own */
#if defined(SNIFF_OTA_URL)
    xTaskCreate(ota_task, "ota", 8192, 0, 2, 0);
#endif
#else
    uart_param_config(UART_PORT, &uc);
    uart_driver_install(UART_PORT, 1024, 64 * 1024, 0, 0, 0);
    nvs_init();
    ESP_ERROR_CHECK(esp_event_loop_create_default());
#endif

    ESP_ERROR_CHECK(esp_wifi_init(&wc));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_channel(CHANNEL, WIFI_SECOND_CHAN_NONE));

    rb = xRingbufferCreate(RING_BYTES, RINGBUF_TYPE_NOSPLIT);
    ESP_ERROR_CHECK(rb ? ESP_OK : ESP_ERR_NO_MEM);

    xTaskCreate(writer_task, "writer", 4096, 0, 5, 0);
#if !defined(SNIFF_COLLECTOR)
    xTaskCreate(time_task,   "time",   2560, 0, 3, 0);
#endif

    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filt));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(sniff_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
}
