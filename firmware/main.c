#define UART_POLLING

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <irq.h>

#include <libbase/uart.h>
#include <libbase/console.h>
#include <generated/csr.h>

#include "udp.c"
#include "uart.c"

static const uint8_t MAC_DST[6] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
static const uint8_t MAC_SRC[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};  
static const uint32_t IP_SRC     = 0xc0a80164;     /* 192.168.1.100 */
static const uint32_t IP_DST     = 0xc0a80165;     /* 192.168.1.101 */
static const uint16_t UDP_PORT_SRC = 1234;
static const uint16_t UDP_PORT_DST = 5678;

static void on_udp(uint32_t src_ip, uint16_t src_port, uint8_t *payload, uint16_t length)
{
    printf("Received %dB from %d.%d.%d.%d:%u : \"%.*s\"\n",
           length,
           (src_ip>>24)&0xFF, (src_ip>>16)&0xFF,
           (src_ip>>8)&0xFF,  src_ip&0xFF,
           src_port, length, payload);
}
static void ethernet_init(void) 
{
    ethphy_crg_reset_write(1);
    busy_wait(200);
    ethphy_crg_reset_write(0);
    busy_wait(200);
}

int main(void) {
    irq_setmask(0);
    irq_setie(1);
    uart_init(); 
    ethernet_init();
    
    udp_set_addr(MAC_SRC, IP_SRC, UDP_PORT_SRC);
    udp_raw_set_callback(on_udp);
    printf("\n=== UDP-UART Bridge ===\n");

    while (1) {    
    	char *str;
    	str = readstr();
    	int len = strlen(str);
   	if(str != NULL){
	    if(udp_raw_send(MAC_DST, IP_DST, UDP_PORT_DST, str, len))
	    	printf("Successfully sent\n");
	    else 
	    	printf("Sending error, try again!\n");
	}
        udp_raw_poll();
    }

    return 0;

}
