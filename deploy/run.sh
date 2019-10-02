#!/bin/sh

deploy=`dirname "$0"`
. $deploy/../../../bin/activate

export PYTHONIOENCODING=utf8
while true; do
    zwrite -c chiron -i prod -m "Starting chiron instance... (args: \"$@\")"
    $deploy/../main.py "$@"
    zwrite -c chiron -i prod -m "Finished running chiron instance (args: \"$@\")."
    sleep 60
done
