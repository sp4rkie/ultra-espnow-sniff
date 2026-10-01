/*
* redacted configuration template - complete, every value is a placeholder
*
* mirrors the structure of the author's mcfg_local.h, including its conditionals, which
* select per-device variants. the real file is pulled in instead of this one when
* MCFG_LOCAL is defined. fill in your own values below.
*/

#define NTP_SERVER                  _w1("pool.ntp.org")
#if !defined OTA_SSID
#define OTA_SSID                    ROTA2K_SSID
#endif
#define ROTA2I_SSID_STR             _w1("name_accesspoint1")
#define ROTA2I_PASSWORD_STR         _w1("pass_accesspoint1")
#define TETHER_SSID_STR             _w1("name_accesspoint2")
#define TETHER_PASSWORD_STR         _w1("pass_accesspoint2")
#define ROTA5G_SSID_STR             _w1("name_accesspoint3")
#define ROTA5G_PASSWORD_STR         _w1("pass_accesspoint3")
#define ROTA2K_SSID_STR             _w1("name_accesspoint4")
#define ROTA2K_PASSWORD_STR         _w1("pass_accesspoint4")
#define SFIRE_SSID_STR              _w1("name_accesspoint5")
#define SFIRE_PASSWORD_STR          _w1("pass_accesspoint5")
#define UFIRE_SSID_STR              _w1("name_accesspoint6")
#define UFIRE_PASSWORD_STR          _w1("pass_accesspoint6")
#define U2FIRE_SSID_STR             _w1("name_accesspoint7")
#define U2FIRE_PASSWORD_STR         _w1("pass_accesspoint7")
#define KFIRE_SSID_STR              _w1("name_accesspoint8")
#define KFIRE_PASSWORD_STR          _w1("pass_accesspoint8")
#define NA_SSID_STR                 _w1("name_accesspoint9")
#define NA_PASSWORD_STR             _w1("pass_accesspoint9")
#define ESPNOW_SSID_STR             _w1("name_accesspoint10")
#define ESPNOW_PASSWORD_STR         _w1("pass_accesspoint10")
#if defined(ESPNOW_TARGET) || defined(ESPNOW_INITIATOR)
#define ESPNOW_UFIRE_CHANNEL        1
#define ESPNOW_TOH_CHANNEL          6
#if !defined(ESPNOW_CHANNEL)
#define ESPNOW_CHANNEL              ESPNOW_TOH_CHANNEL
#endif
#define ESPNOW_USY_GW_MAC           { 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01 }
#define ESPNOW_TOH_GW_MAC           { 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02 }
#if defined(ESPNOW_INITIATOR)
#define ESPNOW_001_GW_MAC           { 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x03 }
#define ESPNOW_002_GW_MAC           { 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x04 }
#define ESPNOW_003_GW_MAC           { 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x05 }
#define ESPNOW_004_GW_MAC           { 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x06 }
#define ESPNOW_005_GW_MAC           { 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x07 }
#define ESPNOW_006_GW_MAC           { 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x08 }
#define ESPNOW_007_GW_MAC           { 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x09 }
#define ESPNOW_008_GW_MAC           { 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x0a }
#define ESPNOW_009_GW_MAC           { 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x0b }
#define ESPNOW_010_GW_MAC           { 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x0c }
#define ESPNOW_BC_GW_MAC            { 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x0d }
#if !defined(ESPNOW_GW_MAC)
#define ESPNOW_GW_MAC               ESPNOW_TOH_GW_MAC
#endif
#endif
#endif
#define RPI5_TARGET_HOST            _w1("host1.example.com")
#define RPI5_TARGET_PORT            8889
#define KARR_TARGET_HOST            _w1("host2.example.com")
#define KARR_TARGET_PORT            8888
#define RPID_TARGET_HOST            _w1("host3.example.com")
#define RPID_TARGET_PORT            8899
#define ROS2_TARGET_HOST            _w1("host4.example.com")
#define ROS2_TARGET_PORT            8888
#define ESPNOW_TARGET_HOST          _w1("host5.example.com")
#define ESPNOW_TARGET_PORT          0
#if !defined(STD_TARGET_HOST)
#define STD_TARGET_HOST             RPI5_TARGET_HOST
#endif
#if !defined(STD_TARGET_PORT)
#define STD_TARGET_PORT             RPI5_TARGET_PORT
#endif
#define URL_FW_DIR                  _w1("host6.example.com")
