#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_LENGTH 512
#define MAX_IP_LENGTH 16

struct LogEntry {
  char remote_addr[MAX_IP_LENGTH];
  char remote_user[MAX_LENGTH];
  char timestamp[MAX_LENGTH];
  char request[MAX_LENGTH];
  int status;
  int bytes_sent;
  char http_referer[MAX_LENGTH];
  char http_user_agent[MAX_LENGTH];
  char http_x_forwarded_for[MAX_LENGTH];
};

void print_log(const struct LogEntry *entry) {
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

struct LogEntry *parse_logs(char *filename, int *logs_len) {
  FILE *fptr = fopen(filename, "r");
  if (!fptr) {
    perror("Could not open fptr");
    return NULL;
  }

  int capacity = 100;
  struct LogEntry *entries = malloc(sizeof(struct LogEntry) * capacity);
  if (!entries) {
    perror("Memory allocation failed");
    return NULL;
  }

  char *line = NULL;
  size_t len = 0;
  int i = 0;

  while (getline(&line, &len, fptr) != -1) {
    if (i >= capacity) {
      capacity *= 2;
      struct LogEntry *temp_entries =
          realloc(entries, sizeof(struct LogEntry) * capacity);
      if (!entries) {
        perror("Could not allocate more memory");
        free(entries);
        free(line);
        fclose(fptr);
        return NULL;
      }
      entries = temp_entries;
    }

    struct LogEntry entry = {0};
    sscanf(line,
           "%s - %s [%[^]]] \"%[^\"]\" %d %d \"%[^\"]\" \"%[^\"]\" \"%[^\"]\"",
           entry.remote_addr, entry.remote_user, entry.timestamp, entry.request,
           &entry.status, &entry.bytes_sent, entry.http_referer,
           entry.http_user_agent, entry.http_x_forwarded_for);

    entries[i] = entry;
    i++;
  }

  free(line);
  fclose(fptr);
  *logs_len = i;
  return entries;
}

void create_summary(struct LogEntry *logs, int len) {
  int failed = 0;
  int unauthed = 0;
  int counts[len];
  char ip_addresses[len][MAX_IP_LENGTH];
  int unique_ip_count = 0;

  char most_frequent_ip[MAX_IP_LENGTH];
  int max_count = 0;

  for (int i = 0; i < len; i++) {
    int status = logs[i].status;
    // 401 Unauthorized or 403 Forbidden
    if (status == 401 || status == 403) {
      unauthed += 1;
    } else if (status >= 400 && status < 500) {
      failed += 1;
    }

    // Count occurrences of each IP address
    int found = 0;
    for (int j = 0; j < unique_ip_count; j++) {
      if (strcmp(logs[i].remote_addr, ip_addresses[j]) == 0) {
        counts[j]++;
        found = 1;
        // Check if this IP now has the maximum count
        if (counts[j] > max_count) {
          max_count = counts[j];
          strcpy(most_frequent_ip, ip_addresses[j]);
        }
        break;
      }
    }
    // New IP address
    if (!found) {
      if (unique_ip_count < len) {
        strcpy(ip_addresses[unique_ip_count], logs[i].remote_addr);
        counts[unique_ip_count] = 1;

        if (counts[unique_ip_count] > max_count) {
          max_count = counts[unique_ip_count];
          strcpy(most_frequent_ip, ip_addresses[unique_ip_count]);
        }
        unique_ip_count++;
      }
    }
  }

  if (max_count > 0) {
    printf("Excessive activity from %s with %d tries\n", most_frequent_ip,
           max_count);
  }
  printf("Summary:\n\tFailed attempts: %d\n\tUnauthorized access: %d\n", failed,
         unauthed);
}

int main(int argc, char *argv[]) {
  char *filename = "/var/log/nginx/access.log";
  int len = 0;
  struct LogEntry *logs = parse_logs(filename, &len);
  if (!logs) {
    return 1;
  }

  int opt;
  int chosen = 0;
  while ((opt = getopt(argc, argv, "s")) != -1) {
    switch (opt) {
    case 's':
      create_summary(logs, len);
      chosen = 1;
      break;
      optind++;
    }
  }

  if (!chosen) {
    printf("Usage: %s <config.json> [options]\n", argv[0]);
    printf("Option:\n\t-s, Print the summary");
    return 1;
  }

  free(logs);
  return 0;
}
