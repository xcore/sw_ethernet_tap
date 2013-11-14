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

#include <ctype.h>

#define DEFAULT_FILE "cap.pcapng"

const char *g_prompt = " > ";

void hook_data_received(int xscope_probe, void *data, int data_len)
{
  // Ignore
}

void hook_exiting()
{
  // Ignore
}

static void print_pkt_ctrl_usage()
{
  printf("  %c <type> <wt> <min> <max> : tell traffic generator to apply specified\n", CMD_PKT_CONTROL);
  printf("               weight(wt) and packet sizes (min and max)\n");
  printf("               for a (u)nicast, (m)ulticast or a (b)roadcast packet type (type)\n");
}

static void print_set_mac_usage()
{
  printf("  %c <u|m> a:b:c:d:e:f       : set the destination MAC address for (u)nicast/(m)ulticast traffic\n", CMD_SET_MAC_ADDRESS);
}

static void print_console_usage()
{
  printf("Supported commands:\n");
  print_pkt_ctrl_usage();
  print_set_mac_usage();
  printf("  %c <ln_rt> : set the line rate for traffic generation\n", CMD_LINE_RATE);
  printf("  %c <s|r|d> : set the generation mode to one of (s)ilent, (r)andom mode or (d)irected\n", CMD_SET_GENERATOR_MODE);
  printf("  %c         : apply the next configuration state and then copy current configuration to next\n", CMD_APPLY_CFG);
  printf("  %c         : swap current configuration with next configuration\n", CMD_SWAP_CFG);
  printf("  %c         : tell traffic generator to display 'directed' packet generation configuration details.\n", CMD_PRINT_PKT_CONFIGURATION);
  printf("  h|?       : print this help message\n");
  printf("  %c         : quit\n", CMD_QUIT);
}

#define LINE_LENGTH 1024

static char get_next_char(const unsigned char **buffer)
{
  const unsigned char *ptr = *buffer;
  int len=0;
  while (*ptr && isspace(*ptr))
    ptr++;

  *buffer = ptr + 1;
  return *ptr;
}

static int convert_atoi_substr(const unsigned char **buffer)
{
  const unsigned char *ptr = *buffer;
  unsigned int value = 0;
  while (*ptr && isspace(*ptr))
    ptr++;

  if (*ptr == '\0')
    return 0;

  value = atoi((char*)ptr);

  while (*ptr && !isspace(*ptr))
    ptr++;

  *buffer = ptr;
  return value;
}

static int validate_pkt_ctrl_setting(const unsigned char *buffer)
{
  char pkt_type = 'z';
  const unsigned char *ptr = &buffer[1]; // Skip command
  int weight = 0;
  int pkt_size_min = 0;
  int pkt_size_max = 0;

  pkt_type = get_next_char(&ptr);

  if ((pkt_type != 'u') && (pkt_type != 'm') && (pkt_type != 'b')) {
    printf("Invalid packet type; specify either a (u)nicast, (m)ulticast or a (b)roadcast packet type \n");
    print_pkt_ctrl_usage();
    return 0;
  }

  weight = convert_atoi_substr(&ptr);
  if ((weight < 0) || (weight > 100)) {
    printf("Invalid weight; specify a value between 1 and 99 \n");
    print_pkt_ctrl_usage();
    return 0;
  }

  if (weight == 0)
    return 1;

  pkt_size_min = convert_atoi_substr(&ptr);
  if ((pkt_size_min <= 0) || (pkt_size_min > 1500)) {
    printf("Invalid min pkt_size; specify a value between 1 and 1500 \n");
    print_pkt_ctrl_usage();
    return 0;
  }

  pkt_size_max = convert_atoi_substr(&ptr);
  if ((pkt_size_max < 1) || (pkt_size_max > 1500)) {
    printf("Invalid max pkt_size; specify a value between 1 and 1500 \n");
    print_pkt_ctrl_usage();
    return 0;
  }

  if (pkt_size_min > pkt_size_max) {
    printf("pkt_size_max value should be greater or equal to pkt_size_min \n");
    print_pkt_ctrl_usage();
    return 0;
  }

  return 1;
}

static int validate_mode(const unsigned char *buffer)
{
  const unsigned char *ptr = &buffer[1]; // Skip command
  char mode = get_next_char(&ptr);

  if ((mode != 's') && (mode != 'r') && (mode != 'd')) {
    printf("Invalid mode; specify any of (s)ilent, (r)andom mode or (d)irected mode\n");
    return 0;
  }

  return 1;
}

static int validate_set_mac_address(const unsigned char *buffer)
{
  const unsigned char *ptr = &buffer[1]; // Skip command
  char type = get_next_char(&ptr);
  int count = 0;
  int error = 0;

  if ((type != 'u') && (type != 'm')) {
    printf("Invalid type; specify (u)nicast or (m)ulticast\n");
    return 0;
  }

  while(1) {
    int byte_len = 0;
    while (isspace(*ptr)) ptr++;
    while (isalnum(*ptr)) {
      byte_len++;
      ptr++;
    }
    if (byte_len > 2)
      error = 1;

    if (*ptr == ':') {
      ptr++;
      count++;
    }

    if (!*ptr || error)
      break;
  }

  if (count == 5 && !error) {
    return 1;
  } else {
    printf("Unable to parse the MAC address. Should be of the form aa:bb:cc:dd:ee:ff\n");
    return 0;
  }
}

static int validate_line_rate(unsigned char *buffer)
{
  const unsigned char *ptr = &buffer[1]; // Skip command
  const unsigned line_rate = convert_atoi_substr(&ptr);
  const double percent_delay = (100.0f/(double)line_rate) - 1.0f;
  const unsigned int rate_factor = (int)(percent_delay * 256.0f);

  if ((ptr == &buffer[1]) || (line_rate > 100)) {
    printf("Invalid line_rate: specify a value between 0 and 100\n");
    return 0;
  }
  sprintf((char*)&buffer[1], " %d", rate_factor);

  // Returning the length of string + null terminator + command
  return 2 + strlen((char*)&buffer[1]);
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
  unsigned char buffer[LINE_LENGTH + 1];
  do {
    int i = 0;
    int j = 0;
    int c = 0;

    printf("%s", g_prompt);
    for (i = 0; (i < LINE_LENGTH) && ((c = getchar()) != EOF) && (c != '\n'); i++)
      buffer[i] = tolower(c);
    buffer[i] = '\0';

    switch (buffer[0]) {
      case CMD_SET_GENERATOR_MODE:
        if (validate_mode(buffer))
          xscope_ep_request_upload(sockfd, 3, buffer);
        break;

      case CMD_PKT_CONTROL:
        if (validate_pkt_ctrl_setting(buffer))
          xscope_ep_request_upload(sockfd, i, buffer);
        break;

      case CMD_LINE_RATE:
        i = validate_line_rate(buffer);
        if (i)
          xscope_ep_request_upload(sockfd, i, buffer);
        break;

      case CMD_SET_MAC_ADDRESS:
          if (validate_set_mac_address(buffer))
            xscope_ep_request_upload(sockfd, i, buffer);
        break;

      case CMD_PRINT_PKT_CONFIGURATION:
      case CMD_SWAP_CFG:
      case CMD_APPLY_CFG:
        xscope_ep_request_upload(sockfd, 1, buffer);
        break;

      case CMD_QUIT:
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
  printf("Usage: %s [-s server_ip] [-p port]\n", argv[0]);
  printf("  -s server_ip :   The IP address of the xscope server (default %s)\n", DEFAULT_SERVER_IP);
  printf("  -p port      :   The port of the xscope server (default %s)\n", DEFAULT_PORT);
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
  int err = 0;
  int sockfd = 0;
  int c = 0;

  while ((c = getopt(argc, argv, "s:p:")) != -1) {
    switch (c) {
      case 's':
        server_ip = optarg;
        break;
      case 'p':
        port_str = optarg;
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

  if (err)
    usage(argv);

  sockfd = initialise_common(server_ip, port_str);

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
