#!/bin/bash

#==========================================================
#   System Request: Debian 7+ / Ubuntu 22.04+
#   Author: ssrlive
#   Description: overTLS onekey support for pure IP or domain certificate and sspanel integration
#   Version: 1.0.0
#
# Usage:
#   ./overtls-install-2026.sh install [--use-sspanel yes|no]
#   ./overtls-install-2026.sh uninstall
#
#   --use-sspanel yes  # enable sspanel integration
#   --use-sspanel no   # disable sspanel integration
#   default: no integration
#==========================================================

#fonts color
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
ColorEnd="\033[0m"

#notification information
Info="${Green}[Info]${ColorEnd}"
OK="${Green}[OK]${ColorEnd}"
Error="${Red}[Error]${ColorEnd}"

function get_binary_target() {
    local _binary_target=""
    local CPU_ARCH=`uname -m`
    case ${CPU_ARCH} in
        x86_64)
            _binary_target="x86_64-unknown-linux-musl"
            ;;
        aarch64)
            _binary_target="aarch64-unknown-linux-musl"
            ;;
        armv7l)
            _binary_target="armv7-unknown-linux-musleabihf"
            ;;
        *)
            echo -e "${Error} ${RedBG} The current CPU architecture ${CPU_ARCH} is not supported. Please contact the author! ${ColorEnd}"
            exit 1
            ;;
    esac
    echo ${_binary_target}
}

cpu_arch_target=$(get_binary_target)

# overtls_install_sh="overtls-install-2026.sh"
# overtls_install_sh_url="https://github.com/ShadowsocksR-Live/overtls/raw/refs/heads/master/install/overtls-install-2026.sh"

overtls_bin_url="https://github.com/shadowsocksr-live/overtls/releases/latest/download/overtls-${cpu_arch_target}.zip"

service_name=overtls-2026
service_unit_file=/etc/systemd/system/${service_name}.service

config_file_path="/etc/overtls/config-2026.json"
target_bin_path="/usr/local/bin/overtls-bin-2026"
web_svr_domain=""
svr_listen_port=443
web_svr_public_ip_addr=""
letsencrypt_cert_file=""
letsencrypt_key_file=""
sspanel_node_id=""
sspanel_server_addr=""
sspanel_api_token=""
use_sspanel="false"

function parse_use_sspanel_value() {
    local val="$1"
    val="$(echo "${val}" | tr '[:upper:]' '[:lower:]')"

    case "${val}" in
        yes|y|true|1)
            use_sspanel="true"
            ;;
        no|n|false|0)
            use_sspanel="false"
            ;;
        *)
            echo -e "${Error} Invalid value for --use-sspanel: ${1}. Use yes/no."
            exit 1
            ;;
    esac
}

function parse_install_options() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --use-sspanel)
                if [[ -z "$2" || "$2" == --* ]]; then
                    echo -e "${Error} Missing value for --use-sspanel"
                    exit 1
                fi
                parse_use_sspanel_value "$2"
                shift 2
                ;;
            --use-sspanel=*)
                parse_use_sspanel_value "${1#*=}"
                shift
                ;;
            *)
                echo -e "${Error} Unknown install option: $1"
                exit 1
                ;;
        esac
    done
}

function random_string_gen() {
    local PASS=""
    local MATRIX="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    local LENGTH=$1
    [ -z $1 ] && LENGTH="16"
    while [ "${n:=1}" -le "$LENGTH" ]
    do
        PASS="$PASS${MATRIX:$(($RANDOM%${#MATRIX})):1}"
        let n+=1
    done

    echo ${PASS}
}

# Reverse proxy entry point.
export reverse_proxy_location=$(random_string_gen 20)

function check_root_account() {
    if [ `id -u` == 0 ]; then
        echo -e "${OK} ${GreenBG} Current account is the root user, enter the installation process ${ColorEnd} "
        sleep 3
    else
        echo -e "${Error} ${RedBG} Current account is not root user, please switch to the root user and re-execute this script ${ColorEnd}"
        exit 1
    fi
}

source /etc/os-release

# Extract the English name of the distribution system from VERSION, in order to add the corresponding nginx apt source under debian / ubuntu
VERSION=`echo ${VERSION} | awk -F "[()]" '{print $2}'`

function script_file_full_path() {
    echo $(readlink -f "$0")
}

function judge() {
    if [[ $? -eq 0 ]]; then
        echo -e "${OK} ${GreenBG} $1 Completed ${ColorEnd}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} $1 Failed ${ColorEnd}"
        exit 1
    fi
}

function dependency_install() {
    apt update -y
    apt install qrencode curl wget git lsof nginx-extras cron bc unzip vim autoconf libtool openssl libssl-dev -y
    if [[ "${ID}" == "ubuntu" && `echo "${VERSION_ID}" | cut -d '.' -f1` -ge 20 ]]; then
        apt install inetutils-ping -y
    fi

    judge "Installing dependencies"
}

function random_listen_port() {
    local overtls_port=0
    while true; do
        overtls_port=$(shuf -i 9000-19999 -n 1)
        expr ${overtls_port} + 1 &>/dev/null
        if [ $? -eq 0 ]; then
            if [ ${overtls_port} -ge 1 ] && [ ${overtls_port} -le 65535 ] && [ ${overtls_port:0:1} != 0 ]; then
                break
            fi
        fi
    done
    echo ${overtls_port}
}

function check_file_exists() {
    local file_path="${1}"

    if [ ! -f "${file_path}" ]; then
        echo -e "${RedBG} Error: ${file_path} not found. ${ColorEnd}"
        exit 1
    fi
}

function get_vps_valid_ip() {
    local web_svr_local_ip_v4_addr=`curl -4 ip.sb 2>/dev/null`
    local web_svr_local_ip_v6_addr=`curl -6 ip.sb 2>/dev/null`
    local ip_v4_regex='^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    local ip_v6_regex='^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$'
    if [[ $web_svr_local_ip_v4_addr =~ $ip_v4_regex ]]; then
        echo -e "${web_svr_local_ip_v4_addr}"
        return 0
    elif [[ $web_svr_local_ip_v6_addr =~ $ip_v6_regex ]]; then
        echo -e "${web_svr_local_ip_v6_addr}"
        return 0
    else
        echo -e "${RedBG} No valid IP found. ${ColorEnd}"
        return 1
    fi
}

function download_n_install_overtls_server_bin() {
    local overtls_bin_zip_file="overtls.zip"
    local local_target_bin_path="${1}"
    local overtls_bin_name="overtls-bin"

    rm -rf ${overtls_bin_zip_file}
    curl -L ${overtls_bin_url} -o ${overtls_bin_zip_file} >/dev/null 2>&1
    if [ $? -ne 0 ]; then echo "curl failed"; exit -1; fi

    rm -rf ${overtls_bin_name}
    unzip ${overtls_bin_zip_file} ${overtls_bin_name} >/dev/null 2>&1
    if [ $? -ne 0 ]; then echo "unzip failed"; exit -1; fi

    chmod +x ${overtls_bin_name}
    rm -rf ${overtls_bin_zip_file}

    rm -rf ${local_target_bin_path}
    local target_dir="$(dirname "${local_target_bin_path}")"
    mkdir -p "${target_dir}"
    mv ${overtls_bin_name} ${local_target_bin_path}

    echo "${local_target_bin_path}"
}

function write_overtls_config_file() {
    local local_cfg_file_path="${1}"
    local dir_path="$(dirname "${local_cfg_file_path}")"
    mkdir -p "${dir_path}"
    rm -rf "${local_cfg_file_path}"

    local hostname=$(echo $HOSTNAME)
    local short_hostname=${hostname:0:4}
    local identity=$(random_string_gen 4)
    local remarks="${short_hostname}-${identity}"

    local pure_ip_cert_file="${letsencrypt_cert_file}"
    local pure_ip_key_file="${letsencrypt_key_file}"

    cat > ${local_cfg_file_path} <<EOF
{
    "remarks": "${remarks}",
    "tunnel_path": "/${reverse_proxy_location}/",
    "test_timeout_secs": 5,

    "server_settings": {
EOF

    if [[ "${use_sspanel}" == "true" ]]; then
        cat >> ${local_cfg_file_path} <<EOF
        "panel_sync": {
            "enabled": true,
            "node_id": ${sspanel_node_id},
            "api_update_time": 10,
            "webapi_url": "${sspanel_server_addr}",
            "webapi_token": "${sspanel_api_token}"
        },
EOF
    fi

    cat >> ${local_cfg_file_path} <<EOF
        "certfile": "${pure_ip_cert_file}",
        "keyfile": "${pure_ip_key_file}",
        "forward_addr": "http://127.0.0.1:80",
        "listen_host": "0.0.0.0",
        "listen_port": ${svr_listen_port}
    },

    "client_settings": {
        "server_host": "${web_svr_public_ip_addr}",
        "server_port": ${svr_listen_port},
        "server_domain": "${web_svr_domain}",
        "listen_host": "127.0.0.1",
        "listen_port": 1080
    }
}
EOF

    echo "${local_cfg_file_path}"
}

function check_install_systemd_svc_params() {
    local role="${1}"
    local service_bin_path="${2}"
    local local_cfg_file_path="${3}"

    if [[ "${role}" != "server" && "${role}" != "client" ]]; then
        echo -e "${RedBG} Invalid role specified. Must be either 'client' or 'server'. ${ColorEnd}"
        exit 1
    fi

    check_file_exists "${service_bin_path}"
    check_file_exists "${local_cfg_file_path}"
}

function write_service_unit_file() {
    local svc_name=${1}
    local svc_exec_command=${2}
    local service_unit_file_path="${3}"

    cat > "${service_unit_file_path}" <<-EOF
[Unit]
    Description=${svc_name}
    After=network.target
[Service]
    Type=simple
    ExecStart=${svc_exec_command}
    PrivateTmp=true
    Restart=on-failure
    RestartSec=35s
    LimitNOFILE=1000000
    LimitCORE=infinity
[Install]
    WantedBy=multi-user.target
EOF

    chmod 754 "${service_unit_file_path}"
}

function create_overtls_systemd_service() {
    local role="${1}"
    local service_bin_path="${2}"
    local local_cfg_file_path="${3}"

    check_install_systemd_svc_params "${role}" "${service_bin_path}" "${local_cfg_file_path}"

    local work_dir="$(dirname $(script_file_full_path))"

    ldconfig
    cd "${work_dir}"

    local command_line="${service_bin_path} -r ${role} -c ${local_cfg_file_path}"

    write_service_unit_file "${service_name}" "${command_line}" "${service_unit_file}"

    echo "${service_name} starting..."

    systemctl enable ${service_name}.service
    sleep 2

    systemctl daemon-reload

    # FIXME: If running script with `service` parameter, this line will failed and cause the script to exit abnormally.
    systemctl start ${service_name}.service
    sleep 2
}

function request_host_or_ip_cert() {
    local host_or_ip=${web_svr_domain}
    local cert_script_url="https://github.com/ssrlive/tips/raw/refs/heads/master/tips/pure-ip-cert.sh"

    curl -L ${cert_script_url} -o pure-ip-cert.sh 2>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "${Error} ${RedBG} Failed to download pure-ip-cert.sh script. Please check your network connection or download it manually from ${cert_script_url} ${ColorEnd}"
        exit 1
    fi
    chmod +x pure-ip-cert.sh
    bash ./pure-ip-cert.sh ${host_or_ip}

    # 证书的各种文件存储在 ~/.acme.sh/${host_or_ip}_ecc 目录下， 其中 ${host_or_ip} 是你当前主机的公网 IP 或 域名。
    letsencrypt_cert_file="${HOME}/.acme.sh/${host_or_ip}_ecc/fullchain.cer"
    letsencrypt_key_file="${HOME}/.acme.sh/${host_or_ip}_ecc/${host_or_ip}.key"
}

function do_uninstall_service_action() {
    ldconfig

    # ${service_stub} status > /dev/null 2>&1
    # if [ $? -eq 0 ]; then
    #     ${service_stub} stop
    # fi

    # if [[ "${ID}" == "ubuntu" || "${ID}" == "debian" || "${ID}" == "linuxmint" ]]; then
    #     update-rc.d -f ${service_name} remove
    # elif [[ "${ID}" == "centos" ]]; then
    #     chkconfig --del ${service_name}
    # fi

    sleep 2

    systemctl stop ${service_name}.service
    sleep 2

    systemctl disable ${service_name}.service

    rm -rf ${config_file_path}
    rm -rf ${target_bin_path}
    rm -rf ${service_unit_file}

    systemctl daemon-reload

    echo -e "${Info} ${GreenBG} ${service_name} uninstall success! ${ColorEnd}"
}

# Uninstall overtls
function uninstall_overtls() {
    printf "Are you sure uninstall ${service_name}? (y/n)\n"
    read -p "(Default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        do_uninstall_service_action
    else
        echo
        echo "uninstall cancelled, nothing to do..."
        echo
    fi
}

function print_url() {
    local ot_exe_path="${1}"
    local ot_cfg_path="${2}"

    check_file_exists "${ot_exe_path}"
    check_file_exists "${ot_cfg_path}"

    local qrcode="$( ${ot_exe_path} -g -c ${ot_cfg_path} )"
    echo "${qrcode}"
    echo
    echo

    qrencode -t UTF8 "${qrcode}" | cat
}

function cron_random_restart_overtls_svc() {
    local random_hour=$(od -An -N1 -i /dev/urandom | awk '{print $1 % 24}')
    local random_minute=$(od -An -N1 -i /dev/urandom | awk '{print $1 % 60}')
    local restart_job_2026="${random_minute} ${random_hour} * * * systemctl restart ${service_name}.service"

    if crontab -l 2>/dev/null | grep -Fq "systemctl restart ${service_name}.service"; then
        echo -e "${OK} ${GreenBG} ${service_name} restart cron job already exists, skipping add. ${ColorEnd}"
        return 0
    fi

    (crontab -l 2>/dev/null; echo "${restart_job_2026}") | crontab -
}

function collect_overtls_server_info() {
    echo ""
    echo -e "${Info} ${GreenBG} ==== Now input some web server information ==== ${ColorEnd} "

    web_svr_public_ip_addr=$(get_vps_valid_ip)
    local exit_status=$?
    if [[ $exit_status -ne 0 ]]; then
        echo -e "${Error} ${RedBG} No valid IP found. ${ColorEnd}"
        exit 1
    fi

    echo ""
    echo "请输入 你的网站域名 (形如 mygooodsite.com), 如果不想输入域名,可直接回车跳过,此时将使用纯 IP 证书"
    echo "Please enter your domain name (for example: mygooodsite.com), if you don't want to enter a domain,"
    stty erase '^H' && read -p "press Enter to skip, in this case, a pure IP (${web_svr_public_ip_addr}) certificate will be used: " domain_name
    [[ -z ${domain_name} ]] && domain_name=${web_svr_public_ip_addr}
    web_svr_domain=${domain_name}

    echo ""
    svr_listen_port=`random_listen_port`
    echo "请输入 站点端口号 (默认值 ${svr_listen_port})"
    stty erase '^H' && read -p "Please enter the access port number (default: ${svr_listen_port}): " port
    [[ -z ${port} ]] && port=${svr_listen_port}
    svr_listen_port=${port}

    echo ""
    echo "请输入 代理入口路径(不带前后斜杠), 默认值 ${reverse_proxy_location} "
    stty erase '^H' && read -p "Please enter reverse proxy path without slashes (default ${reverse_proxy_location}): " rvs_path
    [[ -z ${rvs_path} ]] && rvs_path=${reverse_proxy_location}
    reverse_proxy_location=${rvs_path}

    echo ""
    if [[ "${use_sspanel}" == "true" ]]; then
        echo -e "${Info} ${GreenBG} ==== sspanel integration enabled ==== ${ColorEnd} "
        echo ""
        echo -e "${Info} ${GreenBG} ==== Now input sspanel related information ==== ${ColorEnd} "

        echo ""
        echo "请输入 sspanel 面板内为 本节点服务端 生成的节点 ID (形如 1)"
        stty erase '^H' && read -p "Please enter node ID generated in sspanel (for example: 1): " sspanel_node_id
        if [[ -z ${sspanel_node_id} ]]; then
            echo -e "${Error} ${RedBG} Node ID cannot be empty! ${ColorEnd}"
            exit 1
        fi

        echo ""
        echo "请输入 sspanel 服务器的 API 地址 (形如 https://mysspanel.com 或 https://mysspanel.com:6543)"
        stty erase '^H' && read -p "Please enter sspanel server address (for example: https://mysspanel.com or https://mysspanel.com:6543): " sspanel_server_addr
        if [[ -z ${sspanel_server_addr} ]]; then
            echo -e "${Error} ${RedBG} sspanel server address cannot be empty! ${ColorEnd}"
            exit 1
        fi

        echo ""
        echo "请输入 sspanel 面板内的 API Token (形如 1234567890abcdef)"
        stty erase '^H' && read -p "Please enter API Token (for example: 1234567890abcdef): " sspanel_api_token
        if [[ -z ${sspanel_api_token} ]]; then
            echo -e "${Error} ${RedBG} API Token cannot be empty! ${ColorEnd}"
            exit 1
        fi
    else
        echo -e "${Info} ${GreenBG} ==== sspanel integration disabled (default), skipping sspanel prompts ==== ${ColorEnd} "
        echo -e "${Info} To enable sspanel integration, run with --use-sspanel yes."
    fi

    echo ""
    echo -e "${Info} ${GreenBG} ==== Now all information has been collected, starting installation ==== ${ColorEnd} "
    echo ""
}

function install_overtls_remote_server() {
    dependency_install
    collect_overtls_server_info

    do_uninstall_service_action

    request_host_or_ip_cert

    local svc_bin_path=$(download_n_install_overtls_server_bin "${target_bin_path}")
    echo -e "${OK} ${GreenBG} ${service_name} binary installed at ${svc_bin_path} ${ColorEnd}"

    local cfg_path=$(write_overtls_config_file "${config_file_path}")
    echo -e "${OK} ${GreenBG} ${service_name} config file written at ${cfg_path} ${ColorEnd}"

    if ! [ -f "${svc_bin_path}" ]; then
        echo -e "${Error} ${RedBG} ${service_name} install failed, please contact the author! ${ColorEnd}"
        exit 1
    fi
    create_overtls_systemd_service "server" "${svc_bin_path}" "${cfg_path}"

    cron_random_restart_overtls_svc

    echo
    echo "======== config.json ========"
    echo
    cat ${cfg_path}
    echo
    echo "============================="
    echo

    if [[ "${use_sspanel}" == "true" ]]; then
        echo -e "${OK} ${GreenBG} ${service_name} installed successfully with sspanel integration! ${ColorEnd}"
        echo ""
        echo -e "${Info} ${GreenBG} 请将上面 分隔线内的 config.json 内容复制到 sspanel 面板内的 本节点服务端 的 自定义配置 编辑框中 ${ColorEnd}"
        echo -e "${Info} ${GreenBG} Please copy the config.json content between the lines above into the custom configuration box of the node service in sspanel. ${ColorEnd}"
    else
        print_url "${svc_bin_path}" "${cfg_path}"
    fi
    echo ""
}

function main() {
    echo
    echo "####################################################################"
    echo "# Script of Install ${service_name} Server with pure IP or domain certificate"
    echo "# Author: ssrlive"
    echo "# Github: https://github.com/shadowsocksr-live/overtls"
    echo "####################################################################"
    echo

    local action=${1}
    shift
    [ -z "${action}" ] && action="install"
    case "${action}" in
        install)
            parse_install_options "$@"
            check_root_account
            install_overtls_remote_server
            ;;
        uninstall)
            check_root_account
            uninstall_overtls
            ;;
        *)
            echo "Arguments error! [${action}]"
            echo "Usage: $(basename "$0") install [--use-sspanel yes|no]"
            echo "       $(basename "$0") uninstall"
            echo
            echo "Example: $(basename "$0") install --use-sspanel yes"
            ;;
    esac

    exit 0
}

main "$@"
