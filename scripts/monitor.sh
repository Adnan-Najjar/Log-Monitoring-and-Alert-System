#!/bin/bash

# make a cron job to run every 2 hours
old_crons=$(crontab -l 2> /dev/null)
if [[ $old_crons != *"logParser"* ]]; then
(  echo $old_crons; echo "0 2 * * * ./bin/logParser" ) | crontab - 2> /dev/null
fi

# Remove old alerts
rm -f /var/log/nginx/access_log.bak
# Archive new ones
mv -f /var/log/nginx/access.log /var/log/nginx/access_log.bak
