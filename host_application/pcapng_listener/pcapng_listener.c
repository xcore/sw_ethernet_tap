/*
 * Note that the device and listener should be run with the same port and IP.
 * For example:
 *
 *  xrun --xscope-realtime --xscope-port 127.0.0.1:12346 ...
 *
 *  ./pcapng_listener 127.0.0.1 12346
 *
 */
#include "shared.h"
#include "avb_tester.h"

/*
 * Includes for thread support
 */
#ifdef _WIN32
  #include <winsock.h>
#else
  #include <pthread.h>
#endif

FILE *g_pcap_fptr = NULL;
const char *g_prompt = " > ";

void hook_data_received(void *data, int data_len)
{
  fwrite(data, data_len, 1, g_pcap_fptr);
}

void hook_exiting()
{
  fflush(g_pcap_fptr);
  fclose(g_pcap_fptr);
}

void print_console_usage()
{
  printf("Supported commands:\n");
  printf("  h|?     : print this help message\n");
  printf("  e <o|n> : tell app to expect (o)versubscribed or (n)ormal traffic\n");
  printf("  x <e|d> : tell app to (e)nable or (d)isable xscope packet dumping\n");
  printf("  q       : quit\n");
}

#define LINE_LENGTH 1024

char get_next_char(char *buffer)
{
  char *ptr = buffer;
  while (*ptr && isspace(*ptr))
    ptr++;
  return *ptr;
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

    if (buffer[0] == 'q') {
      print_and_exit("Done\n");

    } else if (buffer[0] == 'e') {
      tester_command_t cmd = AVB_TESTER_EXPECT_NORMAL;
      if (get_next_char(&buffer[1]) == 'o')
        cmd = AVB_TESTER_EXPECT_OVERSUBSCRIBED;
      xscope_ep_request_upload(sockfd, 4, (char *)&cmd);

    } else if (buffer[0] == 'x') {
      tester_command_t cmd = AVB_TESTER_XSCOPE_PACKETS_DISABLE;
      if (get_next_char(&buffer[1]) == 'e')
        cmd = AVB_TESTER_XSCOPE_PACKETS_ENABLE;
      xscope_ep_request_upload(sockfd, 4, (char *)&cmd);

    } else if ((buffer[0] == 'h') || (buffer[0] == '?')) {
      print_console_usage();

    } else {
      printf("Unrecognised command '%s'\n", buffer);
      print_console_usage();
    }
  } while (1);

#ifdef _WIN32
  return 0;
#else
  return NULL;
#endif
}

int main(int argc, char *argv[])
{
#ifdef _WIN32
  HANDLE thread;
#else
  pthread_t tid;
#endif
  int err = 0;
  int sockfd = initialise_common(argc, argv);

  g_pcap_fptr = fopen("cap.pcapng", "wb");

  // Emit common header and two interface descriptions as there are two on the tap
  emit_section_header_block(g_pcap_fptr);
  emit_interface_description_block(g_pcap_fptr);
  emit_interface_description_block(g_pcap_fptr);

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

