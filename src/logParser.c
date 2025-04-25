#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LENGTH 512

typedef struct {
  char remote_addr[MAX_LENGTH];
  char remote_user[MAX_LENGTH];
  char timestamp[MAX_LENGTH];
  char request[MAX_LENGTH];
  int status;
  int bytes_sent;
  char http_referer[MAX_LENGTH];
  char http_user_agent[MAX_LENGTH];
  char http_x_forwarded_for[MAX_LENGTH];
} LogEntry;

void print_log(const LogEntry *entry) {
  printf("<=======================================================>\n");
  printf("Remote Address:\t%s\n", entry->remote_addr);
  printf("Remote User:\t%s\n", entry->remote_user);
  printf("Timestamp:\t%s\n", entry->timestamp);
  printf("Request:\t%s\n", entry->request);
  printf("Status:\t\t%d\n", entry->status);
  printf("Bytes Sent:\t%d\n", entry->bytes_sent);
  printf("Referer:\t%s\n", entry->http_referer);
  printf("User Agent:\t%s\n", entry->http_user_agent);
  printf("X-Forwarded-For:\t%s\n", entry->http_x_forwarded_for);
  printf("\n");
}

int main() {

  FILE *file = fopen("/var/log/nginx/access.log", "r");
  if (!file) {
    perror("Could not open file");
    return EXIT_FAILURE;
  }

  char *line = NULL;
  size_t len = 0;

  while (getline(&line, &len, file) != -1) {
    LogEntry entry = {0};

    sscanf(line,
           "%s - %s [%[^]]] \"%[^\"]\" %d %d \"%[^\"]\" \"%[^\"]\" \"%[^\"]\"",
           entry.remote_addr, entry.remote_user, entry.timestamp, entry.request,
           &entry.status, &entry.bytes_sent, entry.http_referer,
           entry.http_user_agent, entry.http_x_forwarded_for);

    print_log(&entry);
  }

  free(line);
  fclose(file);
  return 0;
}
