/*
 * Note that the device and listener should be run with the same port and IP.
 * For example:
 *
 *  xrun --xscope-realtime --xscope-port 127.0.0.1:12346 ...
 *
 *  ./traffic_gen_controller -s 127.0.0.1 -p 12346
 *
 */
#include "shared.h"
#include "traffic_gen_host_cmds.h"

/*
 * Includes for thread support
 */
#ifdef _WIN32
  #include <winsock.h>
#else
  #include <pthread.h>
#endif

#define DEFAULT_FILE "cap.pcapng"

FILE *g_pcap_fptr = NULL;
const char *g_prompt = " > ";

// Indicate whether the output should be pcap or pcapng
int g_libpcap_mode = 0;

void hook_data_received(void *data, int data_len)
{
  if (g_libpcap_mode) {
    // Convert the pacpng data from the target to libpcap format
    enhanced_packet_block_t *ehb = (enhanced_packet_block_t *) data;

    // Time resolution in pcapng is 10ns
    uint64_t packet_time = (((uint64_t)ehb->timestamp_high << 32) | ehb->timestamp_low) / 100;
    uint32_t ts_sec = packet_time / 1000000;
    uint32_t ts_usec = packet_time % 1000000;

    pcaprec_hdr_t header = { ts_sec, ts_usec, ehb->captured_len, ehb->packet_len };
    fwrite(&header, sizeof(header), 1, g_pcap_fptr);
    fwrite(&ehb->data, ehb->captured_len, 1, g_pcap_fptr);
    fflush(g_pcap_fptr);
  } else {
    // Emit the pcapng data
    fwrite(data, data_len, 1, g_pcap_fptr);
  }
}

void hook_exiting()
{
  fflush(g_pcap_fptr);
  fclose(g_pcap_fptr);
}

void print_console_usage()
{
  printf("Supported commands:\n");
  printf("  h|?       : print this help message\n");
  printf("  r <ln_rt> : tell traffic generator to use the specified line rate for traffic generation\n");
  printf("  m <s|r|d> : tell traffic generator to use any of the (s)ilent, (r)andom mode or (d)irected mode for traffic generation\n");
  printf("  b <w&s>   : tell traffic generator to generate (b)roadcast packets using specified (w)eight and packet (s)ize\n");
  printf("  x <w&s>   : tell traffic generator to generate multicast(x) packets using specified (w)eight and packet (s)ize\n");
  printf("  u <w&s>   : tell traffic generator to generate (u)nicast packets using specified (w)eight and packet (s)ize\n");
  printf("  e         : tell traffic generator about the end of commands for the current packet generation request.\n");
  printf("              every command sequence must be followed by this command\n");
  printf("  q         : quit\n");
}

#define LINE_LENGTH 1024

static char get_next_char(char *buffer)
{
  char *ptr = buffer;
  while (*ptr && isspace(*ptr))
    ptr++;
  return *ptr;
}

/* This function converts an ascii  string to integer and returns its string length */
static int convert_atoi_substr(const char *buffer, int *len)
{
  char *ptr = buffer;
  int i=0, j=0;
  while (*ptr && isspace(*ptr)) {
	ptr++;
	i++;
  }

  ptr = buffer;
  while (*ptr && !isspace(*ptr)) {
	ptr++;
	j++;
  }

  *len = j;
  return (atoi(&buffer[i]));
}

static int validate_pkt_setting(const char *buffer)
{
  int weight = 0, pkt_size = 0, len = 0;
  weight = convert_atoi_substr(&buffer[2], &len);
  pkt_size = convert_atoi_substr(&buffer[2+len], &len);

  if ((weight <= 0) || (weight > 100)) {
    printf("Invalid weight; specify a value between 1 and 99 \n");
    printf("Specify a valid (w)eight and packet (s)ize \n");
    return 0;
  }

  if ((pkt_size <= 0) || (pkt_size > 1500)) {
    printf("Invalid pkt_size; specify a value between 1 and 1500 \n");
    printf("Specify a valid (w)eight and packet (s)ize \n");
    return 0;
  }

  return 1;
}

static int validate_line_rate(const char *buffer)
{
  unsigned line_rate = 0, len = 0;
  line_rate = convert_atoi_substr(&buffer[2], &len);

  if ((line_rate <= 0) || (line_rate > 100)) {
    printf("Invalid line rate; specify a value between 1 and 99 \n");
    return 0;
  }

  return 1;
}

static int validate_mode(const char *buffer)
{
	char mode;
	mode = get_next_char(&buffer[2]);

  if ((mode != 's') && (mode != 'r') && (mode != 'd')) {
    printf("Invalid mode; specify any of (s)ilent, (r)andom mode or (d)irected mode \n");
    return 0;
  }

  return 1;
}

/*
 * A separate thread to handle user commands to control the target.
 */
#ifdef _WIN32
DWORD WINAPI console_thread(void *arg)
#else
void *console_thread(void *arg)
#endif
{
  int sockfd = *(int *)arg;
  char buffer[LINE_LENGTH + 1];
  do {
    int i = 0;
    int c = 0;

    printf("%s", g_prompt);
    for (i = 0; (i < LINE_LENGTH) && ((c = getchar()) != EOF) && (c != '\n'); i++)
      buffer[i] = tolower(c);
    buffer[i] = '\0';

    switch (buffer[0]) {
      case SET_LINE_RATE:
        if (validate_line_rate(buffer))
          xscope_ep_request_upload(sockfd, i, buffer);
        break;

      case SET_GENERATOR_MODE:
        if (validate_mode(buffer))
          xscope_ep_request_upload(sockfd, 3, buffer);
        break;

      case BROADCAST_SETTING:
      case MULTICAST_SETTING:
      case UNICAST_SETTING:
        if (validate_pkt_setting(buffer))
          xscope_ep_request_upload(sockfd, i, buffer);
	    break;

      case END_OF_CMD:
        xscope_ep_request_upload(sockfd, 1, buffer);
	    break;

      case 'q':
        print_and_exit("Done\n");
        break;

      case 'h':
      case '?':
        print_console_usage();
        break;

      default:
        printf("Unrecognised command '%s'\n", buffer);
        print_console_usage();
        break;
	}
  } while (1);

#ifdef _WIN32
  return 0;
#else
  return NULL;
#endif
}

void usage(char *argv[])
{
  printf("Usage: %s [-s server_ip] [-p port] [-l] [file]\n", argv[0]);
  printf("  -s server_ip :   The IP address of the xscope server (default %s)\n", DEFAULT_SERVER_IP);
  printf("  -p port      :   The port of the xscope server (default %s)\n", DEFAULT_PORT);
  printf("  -l           :   Emit libpcap format instead of pcapng\n");
  printf("  file         :   File name packets are written to (default '%s')\n", DEFAULT_FILE);
  exit(1);
}

int main(int argc, char *argv[])
{
#ifdef _WIN32
  HANDLE thread;
#else
  pthread_t tid;
#endif

  char *server_ip = DEFAULT_SERVER_IP;
  char *port_str = DEFAULT_PORT;
  char *filename = DEFAULT_FILE;
  int err = 0;
  int sockfd = 0;
  int c = 0;

  while ((c = getopt(argc, argv, "ls:p:")) != -1) {
    switch (c) {
      case 's':
        server_ip = optarg;
        break;
      case 'p':
        port_str = optarg;
        break;
      case 'l':
        g_libpcap_mode = 1;
        break;
      case ':': /* -f or -o without operand */
        fprintf(stderr, "Option -%c requires an operand\n", optopt);
        err++;
        break;
      case '?':
        fprintf(stderr, "Unrecognized option: '-%c'\n", optopt);
        err++;
    }
  }
  for ( ; optind < argc; optind++) {
    if (filename != DEFAULT_FILE)
      err++;
    filename = argv[optind];
    break;
  }

  if (err)
    usage(argv);

  sockfd = initialise_common(server_ip, port_str);
  g_pcap_fptr = fopen(filename, "wb");

  if (g_libpcap_mode) {
    // Emit libpcap common header
    emit_pcap_header(g_pcap_fptr);

  } else {
    // Emit common header and two interface descriptions as there are two on the tap
    emit_pcapng_section_header_block(g_pcap_fptr);
    emit_pcapng_interface_description_block(g_pcap_fptr);
    emit_pcapng_interface_description_block(g_pcap_fptr);
  }
  fflush(g_pcap_fptr);

  // Now start the console
#ifdef _WIN32
  thread = CreateThread(NULL, 0, console_thread, &sockfd, 0, NULL);
  if (thread == NULL)
    print_and_exit("ERROR: Failed to create console thread\n");
#else
  err = pthread_create(&tid, NULL, &console_thread, &sockfd);
  if (err != 0)
    print_and_exit("ERROR: Failed to create console thread\n");
#endif

  handle_socket(sockfd);

  return 0;
}

//TODO: to specify the pkt min and max sizes for frames