#!/bin/bash

RESTART_ON_HEALTHCHECK_FAILURE="${RESTART_ON_HEALTHCHECK_FAILURE:-false}"
DEFAULT_LIMIT_PERCENTAGE=35
LIMIT_PERCENTAGE="${HEALTHCHECK_FREE_DISK_SPACE_LIMIT:-${DEFAULT_LIMIT_PERCENTAGE}}"

# exit if free disk space check is not enabled
if [ "${RESTART_ON_HEALTHCHECK_FAILURE}" != "true" ]; then
    exit 0
fi

USED_PERCENTAGE=$(df -P -k "${HEALTHCHECK_FREE_DISK_SPACE_PATH}" | tail -n 1 | awk '{print substr($5, 1, length($5) - 1)}')
FREE_PERCENTAGE=$((100 - USED_PERCENTAGE))

echo "Free disk space in '${HEALTHCHECK_FREE_DISK_SPACE_PATH}': ${FREE_PERCENTAGE}%"

# Compare available space with the limit
if [ "${FREE_PERCENTAGE}" -lt "${LIMIT_PERCENTAGE}" ]; then
    pkill gunicorn
    pkill rabbitmq-server
    exit 1
else
    exit 0
fi