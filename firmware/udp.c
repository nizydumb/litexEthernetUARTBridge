#include <generated/csr.h>
#include <generated/soc.h>
#include <generated/mem.h>

#include <libbase/crc.h>
#include <stdint.h>

#define ETHMAC_EV_SRAM_WRITER	0x1
#define ETHMAC_EV_SRAM_READER	0x1

#ifndef CSR_ETHMAC_PREAMBLE_CRC_ADDR
#define HW_PREAMBLE_CRC 0
#else
#define HW_PREAMBLE_CRC 1
#endif

/*------------------------------------------------------------------*/
/*                         Параметры хоста                          */
/*------------------------------------------------------------------*/
static uint8_t  my_mac[6] = {0x02,0x00,0x00,0x00,0x00,0x01};  
static uint32_t my_ip     = 0x0A0A0A0A;  /* 192.168.1.100 */
static uint16_t my_port = 0x0001;
/*------------------------------------------------------------------*/
/*                       Структуры протоколов                       */
/*------------------------------------------------------------------*/

/* Ethernet */
struct __attribute__((packed)) eth_hdr {
#if !HW_PREAMBLE_CRC
    uint8_t  preamble[8];
#endif
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
};

/* IPv4 */
struct __attribute__((packed)) ip_hdr {
    uint8_t  ver_ihl;          /* =0x45 */
    uint8_t  dscp_ecn;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;       /* DF */
    uint8_t  ttl;              /* 64 */
    uint8_t  proto;            /* 17 = UDP */
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
};

/* UDP */
struct __attribute__((packed)) udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
};

/*-----------------------------------------------------------------*/
/*                       Утилиты функции                           */
/*-----------------------------------------------------------------*/

static inline uint16_t bswap16(uint16_t v)
{
    return (v >> 8) | (v << 8);
}

static inline uint32_t bswap32(uint32_t v)
{
    return  (v >> 24) |
           ((v >> 8)  & 0x0000FF00u) |
           ((v << 8)  & 0x00FF0000u) |
            (v << 24);
}

static uint16_t ip_checksum(uint32_t acc, const void *buf, uint32_t len,
                            int complement)
{
    const uint16_t *p = buf;
    while (len > 1) { acc += *p++; len -= 2; }
    if (len) acc += *(const uint8_t *)p;

    /* переносы */
    while (acc >> 16) acc = (acc & 0xFFFF) + (acc >> 16);

    if (complement) acc = ~acc;
    return (uint16_t)acc ? (uint16_t)acc : 0xFFFF;
}

/*------------------------------------------------------------------*/
/*          Функция установки значений сетевых параметров           */
/*------------------------------------------------------------------*/
void udp_set_addr(const uint8_t mac[6], uint32_t ip, uint16_t port)
{
    for (int i = 0; i < 6; i++) my_mac[i] = mac[i];
    my_ip = ip;
    my_port = port;
}

/*------------------------------------------------------------------*/
/*          Функция отправки сырого пакета в канал                 */
/*------------------------------------------------------------------*/
int udp_raw_send(const uint8_t dst_mac[6], uint32_t dst_ip,
                 uint16_t dst_port, const void *data, uint16_t length)
{
    /* 1. Дождаться свободного TX-слота */
    if (!ethmac_sram_reader_ready_read())
        return 0;   /* занято – пробуйте позже */

    /* 2. Указатель на текущий слот */
    static uint32_t txslot = 0;
    uint8_t *buf = (uint8_t *)(ETHMAC_BASE +
                   ETHMAC_SLOT_SIZE * (ETHMAC_RX_SLOTS + txslot));

    /* 3. Заполняем заголовки ------------------------------------------------*/
    uint32_t idx = 0;

#if !HW_PREAMBLE_CRC
    for (int i = 0; i < 7; i++) buf[idx++] = 0x55;
    buf[idx++] = 0xD5;
#endif

    /* Ethernet */
    struct eth_hdr *eth = (struct eth_hdr *)(buf + idx);
    for (int i = 0; i < 6; i++) { eth->dst[i] = dst_mac[i];
                                  eth->src[i] = my_mac[i]; }
    eth->ethertype = bswap16(0x0800);   /* IPv4 */
    idx += sizeof(struct eth_hdr);

    /* IPv4 */
    struct ip_hdr *ip = (struct ip_hdr *)(buf + idx);
    ip->ver_ihl    = 0x45;
    ip->dscp_ecn   = 0;
    ip->total_len  = bswap16(length + sizeof(struct udp_hdr) +
                             sizeof(struct ip_hdr));
    ip->id         = 0;
    ip->flags_frag = bswap16(0x4000);   /* DF */
    ip->ttl        = 64;
    ip->proto      = 17;
    ip->checksum   = 0;
    ip->src        = bswap32(my_ip);
    ip->dst        = bswap32(dst_ip);
    ip->checksum   = ip_checksum(0, ip, sizeof *ip, 1);
    idx += sizeof(struct ip_hdr);

    /* UDP */
    struct udp_hdr *udp = (struct udp_hdr *)(buf + idx);
    udp->src_port = bswap16(my_port);
    udp->dst_port = bswap16(dst_port);
    udp->len      = bswap16(length + sizeof(struct udp_hdr));
    udp->checksum = 0; 
    idx += sizeof(struct udp_hdr);

    /* 4. Копируем payload */
    const uint8_t *d = data;
    for (uint32_t i = 0; i < length; i++)
        buf[idx++] = d[i];

#if !HW_PREAMBLE_CRC
    /* 6. CRC32 по кадру без преамбулы/CRC */
    uint32_t crc = crc32(buf + 8, idx - 8);
    buf[idx++] =  crc        & 0xFF;
    buf[idx++] = (crc >> 8 ) & 0xFF;
    buf[idx++] = (crc >> 16) & 0xFF;
    buf[idx++] = (crc >> 24) & 0xFF;
#endif

    /* 7. Отправляем ---------------------------------------------------------*/
    uint16_t txlen = idx;              /* итоговая длина байт */
    if (txlen < 60) txlen = 60;        /* минимум Ethernet */

    ethmac_sram_reader_slot_write(txslot);
    ethmac_sram_reader_length_write(txlen);
    ethmac_sram_reader_start_write(1);

    txslot = (txslot + 1) % ETHMAC_TX_SLOTS;
    return 1;
}


typedef void (*udp_raw_rx_cb)(uint32_t src_ip,
                              uint16_t src_port,
                              uint8_t *payload,
                              uint16_t length);
                              
static udp_raw_rx_cb user_cb     = 0;


/*------------------------------------------------------------------*/
/*          Функция установки callback для принятого пакета         */
/*------------------------------------------------------------------*/
void udp_raw_set_callback(udp_raw_rx_cb cb) { user_cb = cb; }

static int mac_equal(const uint8_t *a, const uint8_t *b)
{
    for (int i = 0; i < 6; i++) if (a[i] != b[i]) return 0;
    return 1;
}

static uint32_t rxslot = 0;

/*------------------------------------------------------------------*/
/*                  Функция приема UDP пакета                       */
/*------------------------------------------------------------------*/
void udp_raw_poll(void)
{
    /* Проверяем, пришёл ли кадр */
    if (!(ethmac_sram_writer_ev_pending_read() & ETHMAC_EV_SRAM_WRITER))
        return;

    /* Читаем метаданные */
    rxslot   = ethmac_sram_writer_slot_read();
    uint8_t *buf = (uint8_t *)(ETHMAC_BASE + ETHMAC_SLOT_SIZE * rxslot);
    uint16_t len = ethmac_sram_writer_length_read();

    /* Сбрасываем событие заранее, чтобы не потерять следующее */
    ethmac_sram_writer_ev_pending_write(ETHMAC_EV_SRAM_WRITER);

    /* --- базовые проверки ------------------------------------------------- */
#if !HW_PREAMBLE_CRC
    if (len < 64) return;                      /* слишком коротко */

    /* проверка преамбулы */
    for (int i = 0; i < 7; i++) if (buf[i] != 0x55) return;
    if (buf[7] != 0xD5) return;

    /* проверяем CRC */
    uint32_t recv_crc = (buf[len-1] << 24) |
                        (buf[len-2] << 16) |
                        (buf[len-3] <<  8) |
                         buf[len-4];
    uint32_t calc_crc = crc32(buf + 8, len - 12);
    if (recv_crc != calc_crc) return;

    len -= 4;          /* отбрасываем CRC, чтобы смещения совпадали */
    buf += 8;          /* пропускаем преамбулу при дальнейшем разборе */
#endif

    struct eth_hdr *eth = (struct eth_hdr *)buf;
    if (!mac_equal(eth->dst, my_mac) && eth->dst[0] != 0xFF)
        return;        /* не нам и не broadcast */

    if (bswap16(eth->ethertype) != 0x0800)      /* не IPv4 */
        return;

    /* ----------------- IPv4 + UDP разбор ---------------------------------- */
    struct ip_hdr *ip = (struct ip_hdr *)(eth + 1);
    if (ip->proto != 17 || ip->ver_ihl != 0x45)
        return;

    if (bswap32(ip->dst) != my_ip)
        return;        /* чужой IP */

    uint16_t ip_len = bswap16(ip->total_len);
    if (ip_len < sizeof(struct ip_hdr) + sizeof(struct udp_hdr))
        return;

    struct udp_hdr *udp = (struct udp_hdr *)((uint8_t *)ip + sizeof(struct ip_hdr));
    uint16_t udp_len = bswap16(udp->len);
    if (udp_len < sizeof(struct udp_hdr))
        return;
    if(bswap16(udp->dst_port) != my_port)
    	return;

    uint8_t *payload = (uint8_t *)(udp + 1);
    uint16_t data_len = udp_len - sizeof(struct udp_hdr);

    /* --------------- передаём пользователю ----------------------------------- */
    if (user_cb)
        user_cb(bswap32(ip->src),
                bswap16(udp->src_port),
                payload,
                data_len);
}



