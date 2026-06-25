#!/usr/bin/env sh
set -eu

if [ "$#" -eq 0 ]; then
	exec zap-kb -h
fi

case "$1" in
	zap-kb|zap.sh|scan-zap.sh|zap_run_artifact.py|python|python3|sh|bash)
		exec "$@"
		;;
	atlassian|config|expired|merge|onboard|pull|report|taxonomy|-*)
		exec zap-kb "$@"
		;;
	*)
		exec "$@"
		;;
esac
