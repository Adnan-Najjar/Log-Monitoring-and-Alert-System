#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#define MAX_LENGTH 512
#define MAX_IP_LENGTH 45

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

struct Config {
  int max_failed_attempts;
  int max_unauthorized;
};

struct Alerts {
  int failed_attempts;
  int unauthorized;
  char sus_ip[MAX_IP_LENGTH];
  int sus_ip_attempts;
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
    perror("Could not open log file");
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

struct Alerts create_alerts(struct LogEntry *logs, int len) {
  struct Alerts alert = {};
  int counts[len];
  char ip_addresses[len][MAX_IP_LENGTH];
  int unique_ip_count = 0;

  for (int i = 0; i < len; i++) {
    int status = logs[i].status;
    // 401 Unauthorized or 403 Forbidden
    if (status == 401 || status == 403) {
      alert.unauthorized += 1;
    } else if (status >= 400 && status < 500) {
      alert.failed_attempts += 1;
    }

    // Get max IP occurance
    int found = 0;
    for (int j = 0; j < unique_ip_count; j++) {
      if (strcmp(logs[i].remote_addr, ip_addresses[j]) == 0) {
        counts[j]++;
        found = 1;

        if (counts[j] > alert.sus_ip_attempts) {
          alert.sus_ip_attempts = counts[j];
          strcpy(alert.sus_ip, ip_addresses[j]);
        }
        break;
      }
    }
    // New IP address
    if (!found) {
      if (unique_ip_count < len) {
        strcpy(ip_addresses[unique_ip_count], logs[i].remote_addr);
        counts[unique_ip_count] = 1;

        if (counts[unique_ip_count] > alert.sus_ip_attempts) {
          alert.sus_ip_attempts = counts[unique_ip_count];
          strcpy(alert.sus_ip, ip_addresses[unique_ip_count]);
        }
        unique_ip_count++;
      }
    }
  }
  return alert;
}

struct LogEntry *filter_logs(struct LogEntry *logs, int *len,
                             struct LogEntry *filters) {
  int new_len = 0;
  int capacity = 100;
  struct LogEntry *output = malloc(sizeof(struct LogEntry) * capacity);
  if (!output) {
    perror("Memory allocation failed");
    return NULL;
  }

  for (int i = 0; i < *len; i++) {
    struct LogEntry entry = logs[i];

    if (i >= capacity) {
      capacity *= 2;
      struct LogEntry *temp_output =
          realloc(output, sizeof(struct LogEntry) * capacity);
      if (!output) {
        perror("Could not allocate more memory");
        free(output);
        return NULL;
      }
      output = temp_output;
    }

    // Check if filters are valid, then us them
    if ((filters->remote_addr[0] != '\0' &&
         strcmp(entry.remote_addr, filters->remote_addr) == 0) ||
        (filters->timestamp[0] != '\0' &&
         strcmp(entry.timestamp, filters->timestamp) == 0) ||
        (filters->request[0] != '\0' &&
         strcmp(entry.request, filters->request) == 0) ||
        (filters->status != 0 && entry.status == filters->status) ||
        (filters->bytes_sent != 0 && entry.bytes_sent == filters->bytes_sent) ||
        (filters->http_referer[0] != '\0' &&
         strcmp(entry.http_referer, filters->http_referer) == 0) ||
        (filters->http_user_agent[0] != '\0' &&
         strcmp(entry.http_user_agent, filters->http_user_agent) == 0) ||
        (filters->http_x_forwarded_for[0] != '\0' &&
         strcmp(entry.http_x_forwarded_for, filters->http_x_forwarded_for) ==
             0)) {
      new_len++;
      output[new_len] = entry;
    }
  }
  *len = new_len;
  return output;
}

void print_help() {
  printf("\n==This program parses nginx access logs==\n");
  printf("Option:\n\t-p, Print all parsed logs\n");
  printf("\t-a <address>, Filter by Remote Address\n");
  printf("\t-u <user>, Filter by Remote User\n");
  printf("\t-t <timestamp>, Filter by Timestamp\n");
  printf("\t-r <request>, Filter by client Request\n");
  printf("\t-s <status>, Filter by request Status\n");
  printf("\t-b <bytes size>, Filter by Bytes sent\n");
  printf("\t-f <referer>, Filter by Referer\n");
  printf("\t-g <user agent>, Filter by User Agent\n");
  printf("\t-x <forworder for>, Filter by X Forwarder For\n");
  return;
}

struct Config parse_config(FILE *fptr) {
  char delimter[4] = " = ";
  char line[MAX_LENGTH];
  struct Config config;
  while (fgets(line, MAX_LENGTH, fptr) != NULL) {
    char *key = strtok(line, delimter);
    char *value = strtok(NULL, delimter);
    if (strcmp(key, "max_failed_attempts") == 0) {
      config.max_failed_attempts = atoi(value);
    } else if (strcmp(key, "max_unauthorized") == 0) {
      config.max_unauthorized = atoi(value);
    }
  }

  return config;
}

int main(int argc, char *argv[]) {

  if (argc < 2) {
    printf("Usage: %s <config.json> [options]\n", argv[0]);
    print_help();
    return 1;
  }

  // Parse config file
  FILE *config_file = fopen(argv[1], "r");
  if (!config_file) {
    printf("Config file '%s' does not exist.\n", argv[1]);
    printf("Usage: %s <config.json> [options]\n", argv[0]);
    return 1;
  }
  struct Config config = parse_config(config_file);
  fclose(config_file);

  // Parse log file
  char *filename = "/var/log/nginx/access.log";
  int len = 0;
  struct LogEntry *logs = parse_logs(filename, &len);
  if (!logs) {
    return 1;
  }

  int opt;
  int print_filtered_logs = 0;
  int is_filtered = 0;
  struct LogEntry filters = {0};

  while ((opt = getopt(argc, argv, "pa:u:t:r:s:b:f:g:x:")) != -1) {
    switch (opt) {
    case 'p':
      print_filtered_logs = 1;
      break;
    case 'a':
      printf("Remote Address: %s\n", optarg);
      is_filtered = 1;
      strncpy(filters.remote_addr, optarg, MAX_IP_LENGTH);
      break;
    case 'u':
      printf("Remote User: %s\n", optarg);
      is_filtered = 1;
      strncpy(filters.remote_user, optarg, MAX_LENGTH);
      break;
    case 't':
      printf("Timestamp: %s\n", optarg);
      is_filtered = 1;
      strncpy(filters.timestamp, optarg, MAX_LENGTH);
      break;
    case 'r':
      printf("Client Request: %s\n", optarg);
      is_filtered = 1;
      strncpy(filters.request, optarg, MAX_LENGTH);
      break;
    case 's':
      printf("Request Status: %s\n", optarg);
      is_filtered = 1;
      filters.status = atoi(optarg);
      break;
    case 'b':
      printf("Bytes sent: %s\n", optarg);
      is_filtered = 1;
      filters.bytes_sent = atoi(optarg);
      break;
    case 'f':
      printf("Referer: %s\n", optarg);
      is_filtered = 1;
      strncpy(filters.http_referer, optarg, MAX_LENGTH);
      break;
    case 'g':
      printf("User Agent: %s\n", optarg);
      is_filtered = 1;
      strncpy(filters.http_user_agent, optarg, MAX_LENGTH);
      break;
    case 'x':
      printf("X Forwarder For: %s\n", optarg);
      is_filtered = 1;
      strncpy(filters.http_x_forwarded_for, optarg, MAX_LENGTH);
      break;
    default:
      fprintf(stderr, "Unknown option: %c\n", optopt);
      printf("Usage: %s <config.json> [options]\n", argv[0]);
      print_help();
      break;
    }
  }

  struct LogEntry *filtered_logs;
  if (is_filtered) {
    filtered_logs = filter_logs(logs, &len, &filters);
  } else {
    filtered_logs = logs;
  }

  if (print_filtered_logs) {
    printf("---------------Filtered Logs---------------\n");
    for (int i = 0; i < len; i++) {
      print_log(&filtered_logs[i]);
    }
  }
  printf("---------------Summary---------------\n");
  struct Alerts alerts = create_alerts(filtered_logs, len);
  printf("Failed attempts:\t%d\nUnauthorized access:\t%d\n",
         alerts.failed_attempts, alerts.unauthorized);

  FILE *fout = fopen("alerts.txt", "a");
  if (!fout) {
    perror("Could not create alerts.txt file.");
    free(filtered_logs);
    free(logs);
    return 1;
  }

  fprintf(fout, "=========%s=========\n", filtered_logs[len - 1].timestamp);
  openlog("nginx", LOG_PID | LOG_CONS, LOG_USER);
  if (alerts.failed_attempts > config.max_failed_attempts) {
    fprintf(fout, "Max Failed attempts exceeded. (%d attempts)\n",
            alerts.failed_attempts);
    syslog(LOG_WARNING, "Max Failed attempts exceeded.");
  }
  if (alerts.unauthorized > config.max_unauthorized) {
    fprintf(fout, "Max Unauthorized attempts exceeded. (%d attempts)\n",
            alerts.unauthorized);
    syslog(LOG_WARNING, "Max Unauthorized attempts exceeded.");
  }
  if (alerts.sus_ip_attempts > 0) {
    fprintf(fout, "IP with most requests is %s with %d attempts\n",
            alerts.sus_ip, alerts.sus_ip_attempts);
  }

  if (filtered_logs != logs) {
    free(filtered_logs);
  }
  free(logs);
  return 0;
}
