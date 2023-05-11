#!/bin/bash

NAME="overtls"
SVC_BIN_PATH=/usr/bin/overtls
CONFIG_FILE_PATH=/etc/overtls/config.json

cmd_set_log_level="export RUST_LOG=off"
command_start="setsid nohup ${SVC_BIN_PATH} -r server -c ${CONFIG_FILE_PATH}"

PID=0
RETVAL=0

function check_running(){
    PID=$(ps -ef | grep -v grep | grep -i "${SVC_BIN_PATH}" | awk '{print $2}')
    if [ -n "${PID}" ]; then
        return 0
    else
        return 1
    fi
}

function do_start(){
    check_running
    if [ $? -eq 0 ]; then
        echo "${NAME} (pid ${PID}) is already running..."
        exit 0
    else
        ${cmd_set_log_level}
        ${command_start} &
        RETVAL=$?
        if [ ${RETVAL} -eq 0 ]; then
            echo "Starting ${NAME} success"
        else
            echo "Starting ${NAME} failed"
        fi
    fi
}

function do_stop(){
    check_running
    if [ $? -eq 0 ]; then
        kill ${PID}
        RETVAL=$?
        if [ ${RETVAL} -eq 0 ]; then
            echo "Stopping ${NAME} success"
        else
            echo "Stopping ${NAME} failed"
        fi
    else
        echo "${NAME} is stopped"
        RETVAL=1
    fi
}

function do_status(){
    check_running
    if [ $? -eq 0 ]; then
        echo "${NAME} (pid ${PID}) is running..."
    else
        echo "${NAME} is stopped"
        RETVAL=1
    fi
}

function do_restart(){
    do_stop
    sleep 0.5
    do_start
}

case "${1}" in
    start|stop|restart|status)
        do_${1}
        ;;
    *)
        echo "Usage: ${0} { start | stop | restart | status }"
        RETVAL=1
        ;;
esac

exit ${RETVAL}
