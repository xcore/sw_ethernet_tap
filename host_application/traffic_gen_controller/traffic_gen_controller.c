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
#include "traffic_ctlr_host_cmds.h"

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
char g_generator_mode = 's';  //indicates mode of the device generator

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

void print_traffic_gen_cmd_usage()
{
  printf("  c <pkt_typ & wt & sz_min & sz_max> : tell traffic generator to apply specified weight(wt) and packet sizes (sz_min and sz_max) \n");
  printf("              for a (u)nicast, (m)ulticast or a (b)roadcast packet type (pkt_typ)\n");
}

void print_traffic_gen_controller_cmd_usage()
{
  printf("  g <pkt_typ & wt & ln_rt>         : tell traffic generator to control packet generation for a (u)nicast, (m)ulticast \n");
  printf("              or a (b)roadcast packet type (pkt_typ) by applying specified weight (wt) and line rate (ln_rt) \n");
}

void print_console_usage()
{
  printf("Supported commands:\n");
  printf("  h|?       : print this help message\n");
//  printf("  r <ln_rt> : tell traffic generator to use the specified line rate for traffic generation\n");
  printf("  m <s|r|d> : tell traffic generator to use any of the (s)ilent, (r)andom mode or (d)irected mode for traffic generation\n");
  print_traffic_gen_cmd_usage();
  print_traffic_gen_controller_cmd_usage();
  printf("  e         : tell traffic generator about the end of commands for the current packet generation request.\n");
  printf("              every command sequence must be followed by this command for any (d)irected generation requests\n");
  printf("  p         : tell traffic generator to display 'directed' packet generation configuration details.\n");
  printf("  q         : quit\n");
}

#define LINE_LENGTH 1024

static char get_next_char(char *buffer)
{
  char *ptr = buffer;
  int len=0;
  while (*ptr && isspace(*ptr))
    ptr++;

  return *ptr;
}

static char get_next_string(char *buffer, int *str_len)
{
  char *str_ptr = buffer;
  char *ptr = buffer;
  int len=0;

  while (*str_ptr && isspace(*str_ptr))
    str_ptr++;

  while (*ptr && !isspace(*ptr)) {
	ptr++;
	len++;
  }

  *str_len = len;
  return *str_ptr;
}


/* This function converts an ascii string to integer and returns its string length */
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

static int validate_directed_mode_setting()
{
  if (g_generator_mode == 'd') {
    printf("Packet generator is running in (d)irected mode! \n");
    printf("Change the mode to (s)ilent or (r)andom before modifying directed mode configuration. \n");
    return 0;
  }

  return 1;
}

static int validate_pkt_ctrl_setting(const char *buffer)
{
  int len = 0;
  char pkt_type = 'z';
  int index = 0;
  int weight = 0;
  int pkt_size_min = 0;
  int pkt_size_max = 0;

  if (!validate_directed_mode_setting())
    return 0;

  index = 2; //after ignoring the command and white space
  pkt_type = get_next_string(&buffer[2], &len);

  if ((pkt_type != 'u') && (pkt_type != 'm') && (pkt_type != 'b')) {
    printf("Invalid packet type; specify either a (u)nicast, (m)ulticast or a (b)roadcast packet type \n");
    print_traffic_gen_cmd_usage();
    return 0;
  }

  index += len+1; //1 for white space
  weight = convert_atoi_substr(&buffer[index], &len);
  if ((weight <= 0) || (weight > 100)) {
    printf("Invalid weight; specify a value between 1 and 99 \n");
    print_traffic_gen_cmd_usage();
    return 0;
  }


  index += len+1;
  pkt_size_min = convert_atoi_substr(&buffer[index], &len);
  if ((pkt_size_min <= 0) || (pkt_size_min > 1500)) {
    printf("Invalid min pkt_size; specify a value between 1 and 1500 \n");
    print_traffic_gen_cmd_usage();
    return 0;
  }

  index += len+1;
  pkt_size_max = convert_atoi_substr(&buffer[index], &len);
  if ((pkt_size_max < 1) || (pkt_size_max > 1500)) {
    printf("Invalid max pkt_size; specify a value between 1 and 1500 \n");
    print_traffic_gen_cmd_usage();
    return 0;
  }

  if (pkt_size_min > pkt_size_max) {
    printf("pkt_size_max value should be greater or equal to pkt_size_min \n");
    print_traffic_gen_cmd_usage();
    return 0;
  }

  return 1;
}


static int validate_pkt_generation_ctrl_setting(const char *buffer)
{
  int len = 0;
  char pkt_type = 'z';
  int index = 0;
  int weight = 0;
  int rate = 0;

  if (!validate_directed_mode_setting())
    return 0;

  index = 2; //after ignoring the command and white space
  pkt_type = get_next_string(&buffer[2], &len);

  if ((pkt_type != 'u') && (pkt_type != 'm') && (pkt_type != 'b')) {
    printf("Invalid packet type; specify either a (u)nicast, (m)ulticast or a (b)roadcast packet type \n");
    print_traffic_gen_controller_cmd_usage();
    return 0;
  }

  index += len+1; //1 for white space
  weight = convert_atoi_substr(&buffer[index], &len);
  if ((weight <= 0) || (weight > 100)) {
    printf("Invalid weight; specify a value between 1 and 99 \n");
    print_traffic_gen_controller_cmd_usage();
    return 0;
  }


  index += len+1;
  rate = convert_atoi_substr(&buffer[index], &len);
  if ((rate <= 0) || (rate > 100)) {
    printf("Invalid rate; specify a value between 1 and 100 \n");
    print_traffic_gen_controller_cmd_usage();
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
  else
    g_generator_mode = mode;

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
    int j = 0;
    int c = 0;

    printf("%s", g_prompt);
    for (i = 0; (i < LINE_LENGTH) && ((c = getchar()) != EOF) && (c != '\n'); i++)
      buffer[i] = tolower(c);
    buffer[i] = '\0';

    for (j = i; j < LINE_LENGTH; j++)
      buffer[j] = '\0';

    switch (buffer[0]) {
      case SET_GENERATOR_MODE:
        if (validate_mode(buffer))
          xscope_ep_request_upload(sockfd, 3, buffer);
        break;

      case PKT_CONTROL:
        if (validate_pkt_ctrl_setting(buffer))
          xscope_ep_request_upload(sockfd, i, buffer);
	    break;

      case PKT_GENERATION_CONTROL:
        if (validate_pkt_generation_ctrl_setting(buffer))
          xscope_ep_request_upload(sockfd, i, buffer);
	    break;

      case PRINT_PKT_CONFIGURATION:
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