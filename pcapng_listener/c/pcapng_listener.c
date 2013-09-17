/*
 * Note that the device should be launched with:
 *  xrun --xscope-realtime --xscope-port 127.0.0.1:12346 ...
 */
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 

#include "pcapng.h"

#define CAPTURE_LENGTH 64

void emit_section_header_block(FILE *f)
{
    section_block_header_t header = {
        0x0A0D0D0A,             // Block Type
        32,                     // Block Total Length
        0x1A2B3C4D,             // Byte-Order Magic
        0x1,                    // Major Version
        0x0,                    // Minor Version
        0xffffffffffffffffull,  // Section Length
        0x0,                    // Options
        32                      // Block Total Length
    };
    fwrite(&header, sizeof(header), 1, f);
}

void emit_interface_description_block(FILE *f)
{
    interface_description_block_t interface = {
        0x1,                                    // Block Type
        sizeof(interface_description_block_t),  // Block Total Length
        0x1,                                    // LinkType
        0x0,                                    // Reserved
        CAPTURE_LENGTH,                         // SnapLen
                                                // Options
        { 0x09, 0x01, 0x08 },                       // if_tsresol (10^-8)

        sizeof(interface_description_block_t)   // Block Total Length
    };
    fwrite(&interface, sizeof(interface), 1, f);
}

FILE *g_log = NULL;
FILE *g_pcap = NULL;

void int_handler(int sig)
{
    fflush(g_log);
    fclose(g_log);
    fflush(g_pcap);
    fclose(g_pcap);
    printf("\nFinishing\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    int sockfd = 0;
    int n = 0;
    unsigned char buffer[16384];
    struct sockaddr_in serv_addr; 

    g_log = fopen("run.log", "w");
    g_pcap = fopen("cap.pcapng", "wb");

    signal(SIGINT, int_handler);

    if (argc != 2) {
        printf("Usage: %s <ip of server>\n", argv[0]);
        exit(1);
    } 

    memset(buffer, 0, sizeof(buffer));
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("ERROR: Could not create socket\n");
        exit(1);
    } 

    memset(&serv_addr, 0, sizeof(serv_addr)); 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(12346); 

    if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0) {
        printf("ERROR: inet_pton error occured\n");
        exit(1);
    } 

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
       printf("ERROR: Connect failed\n");
       exit(1);
    } 

    emit_section_header_block(g_pcap);

    // Emit two interface descriptions as there are two on the tap
    emit_interface_description_block(g_pcap);
    emit_interface_description_block(g_pcap);

    // Send the '2' command which is requesting receiving xscope data
    buffer[0] = 2;
    n = send(sockfd, buffer, 1, 0);
    if (n != 1) {
        printf("ERROR: Command send failed\n");
        exit(1);
    }

    printf("Connected\n");

    int total_bytes = 0;
    while ((n = read(sockfd, buffer, sizeof(buffer))) > 0) {
        int i;

        total_bytes += n;
        printf("\r%d", total_bytes);
        
        fprintf(g_log, "Received %d", n);
        for (i = 0; i < n; i++) {
            if ((i % 16) == 0)
                fprintf(g_log, "\n");
            fprintf(g_log, "%02x ", buffer[i]);
        }

        for (i = 0; (i + 4) < n; i += 16) {
            if (buffer[0] != 2) {
                printf("ERROR: Message format corrupted\n");
                exit(1);
            }
            fwrite(&buffer[i + 4], 1, 1, g_pcap);
        }
    } 

    return 0;
}
