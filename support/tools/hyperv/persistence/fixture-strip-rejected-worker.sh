#!/bin/sh
# Rejection-test payload only: a missing build gate would leave this marker.
printf '%s\n' 'rejected persistence candidate executed' > "$0.executed"
exit 79
