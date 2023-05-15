function write_service_description_file() {
    local svc_name=${1}
    local svc_stub=${2}
    local service_desc_file_path="${3}"

    cat > ${service_desc_file_path} <<-EOF
[Unit]
    Description=${svc_name}
    After=network.target
[Service]
    Type=forking
    ExecStart=${svc_stub} start
    ExecReload=${svc_stub} restart
    ExecStop=${svc_stub} stop
    PrivateTmp=true
    Restart=on-failure
    RestartSec=35s
    LimitNOFILE=1000000
    LimitCORE=infinity
[Install]
    WantedBy=multi-user.target
EOF

    chmod 754 ${service_desc_file_path}
}

function write_service_stub_file_for_systemd() {
    local service_name=${1}
    local service_stub_path=${2}
    local service_bin_path=${3}
    local service_full_command_line="${4}"

    cat > ${service_stub_path} <<-EOF
#!/bin/bash

### BEGIN INIT INFO
# Provides:          ${service_name}
# Required-Start:    \$network \$syslog
# Required-Stop:     \$network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       Start or stop the ${service_name} service
### END INIT INFO

NAME=${service_name}
SVC_BIN_PATH=${service_bin_path}

command_start="${service_full_command_line}"

PID=0
RETVAL=0

function check_running(){
    PID=\$(ps -ef | grep -v grep | grep -i "\${SVC_BIN_PATH}" | awk '{print \$2}')
    if [ -n "\${PID}" ]; then
        return 0
    else
        return 1
    fi
}

function do_start(){
    check_running
    if [ \$? -eq 0 ]; then
        echo "\${NAME} (pid \${PID}) is already running..."
        exit 0
    else
        \${command_start}
        RETVAL=\$?
        if [ \${RETVAL} -eq 0 ]; then
            echo "Starting \${NAME} success"
        else
            echo "Starting \${NAME} failed"
        fi
    fi
}

function do_stop(){
    check_running
    if [ \$? -eq 0 ]; then
        kill \${PID}
        RETVAL=\$?
        if [ \${RETVAL} -eq 0 ]; then
            echo "Stopping \${NAME} success"
        else
            echo "Stopping \${NAME} failed"
        fi
    else
        echo "\${NAME} is stopped"
        RETVAL=1
    fi
}

function do_status(){
    check_running
    if [ \$? -eq 0 ]; then
        echo "\${NAME} (pid \${PID}) is running..."
    else
        echo "\${NAME} is stopped"
        RETVAL=1
    fi
}

function do_restart(){
    do_stop
    sleep 0.5
    do_start
}

case "\${1}" in
    start|stop|restart|status)
        do_\${1}
        ;;
    *)
        echo "Usage: \${0} { start | stop | restart | status }"
        RETVAL=1
        ;;
esac

exit \${RETVAL}

EOF

    chmod +x ${service_stub_path}
}
