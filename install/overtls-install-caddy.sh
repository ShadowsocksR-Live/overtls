#!/bin/bash

#==========================================================
#   System Request: Debian 7+ / Ubuntu 14.04+
#   Author: ssrlive
#   Description: overTLS onekey for musl building with Caddy
#   Version: 1.0.0
#==========================================================

#fonts color
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"

#notification information
Info="${Green}[Info]${Font}"
OK="${Green}[OK]${Font}"
Error="${Red}[Error]${Font}"

cur_dir=`pwd`

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
            echo -e "${Error} ${RedBG} The current CPU architecture ${CPU_ARCH} is not supported. Please contact the author! ${Font}"
            exit 1
            ;;
    esac
    echo ${_binary_target}
}

cpu_arch_target=$(get_binary_target)

overtls_install_sh="overtls-install-caddy.sh"
overtls_install_sh_url="https://raw.githubusercontent.com/shadowsocksr-live/overtls/master/install/overtls-install-caddy.sh"

overtls_bin_url="https://github.com/shadowsocksr-live/overtls/releases/latest/download/overtls-${cpu_arch_target}.zip"
overtls_bin_zip_file="overtls-${cpu_arch_target}.zip"

daemon_script_url="https://raw.githubusercontent.com/shadowsocksr-live/overtls/master/install/overtls-daemon.sh"
daemon_script_file="overtls-daemon.sh"
service_dir=/lib/systemd/system
service_name=overtls
service_stub=/etc/init.d/${service_name}

config_file_path="/etc/overtls/config.json"
caddy_conf_file="/etc/caddy/Caddyfile"
site_dir="/fakesite"
site_cert_dir="/fakesite_cert"
target_bin_path="/usr/local/bin/overtls-bin"
bin_name=overtls-bin

export web_svr_domain=""
export web_svr_local_ip_addr=""
export web_svr_listen_port="443"
export web_svr_reverse_proxy_host="127.0.0.1"
export web_svr_reverse_proxy_port=10000

function random_string_gen() {
    local PASS=""
    local MATRIX="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" # "~!@#$%^&*()_+="
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
        echo -e "${OK} ${GreenBG} Current account is the root user, enter the installation process ${Font} "
        sleep 3
    else
        echo -e "${Error} ${RedBG} Current account is not root user, please switch to the root user and re-execute this script ${Font}"
        exit 1
    fi
}

source /etc/os-release

function script_file_full_path() {
    echo $(readlink -f "$0")
}

function judge() {
    if [[ $? -eq 0 ]]; then
        echo -e "${OK} ${GreenBG} $1 Completed ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} $1 Failed ${Font}"
        exit 1
    fi
}

function disable_web_servers() {
    sudo systemctl stop nginx       # stop nginx
    sudo systemctl disable nginx    # disable nginx

    sudo systemctl stop httpd       # stop apache2
    sudo systemctl disable httpd    # disable apache2

    sudo systemctl stop apache2     # stop apache2
    sudo systemctl disable apache2  # disable apache2

    sudo systemctl stop caddy       # stop caddy
    sudo systemctl disable cadddy   # disable caddy
}

function install_caddy_in_debian() {
    if [[ -x /usr/bin/caddy ]]; then
        echo -e "${OK} ${GreenBG} Caddy has been installed before this moment ${Font}"
        sudo systemctl enable caddy
        sudo systemctl start caddy
        return 0
    fi

    # Install caddy, see https://caddyserver.com/docs/install#debian-ubuntu-raspbian
    sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
    sudo apt update
    sudo apt install caddy

    sudo systemctl enable caddy
    sudo systemctl start caddy

    judge "Caddy installation"
}

function dependency_install() {
    apt install curl wget git lsof bc unzip -y
    apt install cron vim curl -y
    apt update -y
    apt install qrencode zlib1g zlib1g-dev autoconf libtool -y
    if [[ "${ID}" == "ubuntu" && `echo "${VERSION_ID}" | cut -d '.' -f1` -ge 20 ]]; then
        apt install inetutils-ping -y
    fi
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

    if [[ -z "${file_path}" ]]; then
        echo -e "${RedBG} Error: file path given is empty. ${Font}"
        exit 1
    fi

    if [ ! -f "${file_path}" ]; then
        echo -e "${RedBG} Error: ${file_path} not found. ${Font}"
        exit 1
    fi
}

function domain_check() {
    local install=""
    echo "请输入 你的网站域名 (形如 mygooodsite.com)"
    stty erase '^H' && read -p "Please enter your domain name (for example: mygooodsite.com): " web_svr_domain
    local web_svr_ip_addr=`ping ${web_svr_domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}' | sed '1{s/[^(]*(//;s/).*//;q}'`
    echo -e "${OK} ${GreenBG} 正獲取公網 IP, 請耐心等待... ${Font}"
    echo -e "${OK} ${GreenBG} Obtaining public IP information, please wait patiently... ${Font}"
    local web_svr_local_ip_v4_addr=`curl -4 ip.sb`
    local web_svr_local_ip_v6_addr=`curl -6 ip.sb`
    echo -e "DNS resolution IP: ${web_svr_ip_addr}"
    echo -e "Local V4 IP: ${web_svr_local_ip_v4_addr}"
    echo -e "Local V6 IP: ${web_svr_local_ip_v6_addr}"
    sleep 2
    if [[ $(echo ${web_svr_local_ip_v4_addr} | tr a-z A-Z) = $(echo ${web_svr_ip_addr} | tr a-z A-Z) ]]; then
        echo -e "${OK} ${GreenBG} The DNS resolution IP matches local V4 IP ${Font}"
        web_svr_local_ip_addr=${web_svr_local_ip_v4_addr}
        sleep 2
    elif [[ $(echo ${web_svr_local_ip_v6_addr} | tr a-z A-Z) = $(echo ${web_svr_ip_addr} | tr a-z A-Z) ]]; then
        echo -e "${OK} ${GreenBG} The DNS resolution IP matches local V6 IP ${Font}"
        web_svr_local_ip_addr=${web_svr_local_ip_v6_addr}
        sleep 2
    else
        echo -e "${Error} ${RedBG} The DNS resolution IP does not match the local IP. Do you want to continue the installation? (y/n) ${Font}" && read install
        case ${install} in
            [yY][eE][sS]|[yY])
                echo -e "${GreenBG} Continue to install ${Font}"
                sleep 2
                ;;
            *)
                echo -e "${RedBG} Installation terminated ${Font}"
                exit 2
                ;;
        esac
    fi
    
    local rvs_path=${reverse_proxy_location}
    echo "请输入 反向代理入口路径(不带前后斜杠), 默认值 ${rvs_path} "
    stty erase '^H' && read -p "Please enter reverse proxy path without slashes (default ${rvs_path}):" rvs_path
    [[ -z ${rvs_path} ]] && rvs_path=${reverse_proxy_location}
    reverse_proxy_location=${rvs_path}
}

function input_web_listen_port() {
    local port="443"
    stty erase '^H' && read -p "Please enter the access port number (default: 443):" port
    [[ -z ${port} ]] && port="443"
    echo ${port}
}

function cron_random_restart_overtls_svc() {
    local random_hour=$(od -An -N1 -i /dev/urandom | awk '{print $1 % 24}')
    local random_minute=$(od -An -N1 -i /dev/urandom | awk '{print $1 % 60}')

    (crontab -l; echo "${random_minute} ${random_hour} * * * systemctl restart overtls") | crontab -
}

function download_n_install_overtls_server_bin() {
    local local_bin_path="${target_bin_path}"

    rm -rf ${overtls_bin_zip_file}
    wget ${overtls_bin_url} >/dev/null 2>&1
    if [ $? -ne 0 ]; then echo "wget failed"; exit -1; fi

    rm -rf ${bin_name}
    unzip ${overtls_bin_zip_file} ${bin_name} >/dev/null 2>&1
    if [ $? -ne 0 ]; then echo "unzip failed"; exit -1; fi

    chmod +x ${bin_name}
    rm -rf ${overtls_bin_zip_file}

    rm -rf ${local_bin_path}
    local target_dir="$(dirname "${local_bin_path}")"
    mv ${bin_name} ${target_dir}

    echo "${local_bin_path}"
}

function write_overtls_config_file() {
    local local_cfg_file_path="${1}"
    local dir_path="$(dirname "${local_cfg_file_path}")"
    mkdir -p "${dir_path}"
    rm -rf "${local_cfg_file_path}"

    local identity=$(random_string_gen 4)

    cat > ${local_cfg_file_path} <<EOF
{
    "remarks": "${identity}",
    "tunnel_path": "/${reverse_proxy_location}/",
    "test_timeout_secs": 5,

    "server_settings": {
        "forward_addr": "http://127.0.0.1:80",
        "listen_host": "${web_svr_reverse_proxy_host}",
        "listen_port": ${web_svr_reverse_proxy_port}
    },

    "client_settings": {
        "server_host": "${web_svr_local_ip_addr}",
        "server_port": ${web_svr_listen_port},
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
        echo -e "${RedBG} Invalid role specified. Must be either 'client' or 'server'. ${Font}"
        exit 1
    fi

    check_file_exists "${service_bin_path}"
    check_file_exists "${local_cfg_file_path}"
}

function create_overtls_systemd_service() {
    local role="${1}"
    local service_bin_path="${2}"
    local local_cfg_file_path="${3}"

    check_install_systemd_svc_params "${role}" "${service_bin_path}" "${local_cfg_file_path}"

    local work_dir="$(dirname $(script_file_full_path))"

    ldconfig
    cd ${work_dir}

    if [ ! -f "./${daemon_script_file}" ]; then
        # Download ${service_name} service script
        if ! curl -L ${daemon_script_url} -o ./${daemon_script_file} ; then
            echo -e "${RedBG} Failed to download ${service_name} service script! ${Font}"
            exit 1
        fi
    fi

    # write_service_description_file and write_service_stub_file_for_systemd are defined in ${daemon_script_file}
    source ./${daemon_script_file}

    local svc_desc_file_path=${service_dir}/${service_name}.service
    write_service_description_file ${service_name} ${service_stub} "${svc_desc_file_path}"

    local command_line="${service_bin_path} -d -r ${role} -c ${local_cfg_file_path}"
    write_service_stub_file_for_systemd "${service_name}" "${service_stub}" "${service_bin_path}" "${command_line}"

    if [[ "${ID}" == "ubuntu" || "${ID}" == "debian" || "${ID}" == "linuxmint" ]]; then
        update-rc.d -f ${service_name} defaults
    elif [[ "${ID}" == "centos" ]]; then
        chkconfig --add ${service_name}
        chkconfig ${service_name} on
    else
        echo "Unsupported OS ${ID}"
        exit 1
    fi

    echo "${service_stub} starting..."

    systemctl enable ${service_name}.service
    sleep 2

    systemctl daemon-reload

    # FIXME: If running script with `service` parameter, this line will failed and cause the script to exit abnormally.
    systemctl start ${service_name}.service
    sleep 2
}

function do_uninstall_service_action() {
    ldconfig

    sleep 2
    disable_web_servers

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
    rm -rf ${service_stub}
    rm -rf ${target_bin_path}
    rm -rf ${service_dir}/${service_name}.service

    systemctl daemon-reload

    echo "${service_name} uninstall success!"
}

function install_binary_as_systemd_service() {
    local role="${1}"
    local local_bin_file_path=${2}
    local local_cfg_file_path=${3}

    check_install_systemd_svc_params "${role}" "${local_bin_file_path}" "${local_cfg_file_path}"

    if systemctl is-active --quiet ${service_name} ; then
        echo "${service_name} is running"
        echo -e "${Error} ${RedBG} Do you want to remove ${service_name} really and install a new one? (Y/N) ${Font}" && read action
        case ${action} in
            [yY][eE][sS]|[yY])
                echo -e "${GreenBG} Continue to install ${Font}"
                sleep 2
                ;;
            *)
                echo -e "${RedBG} Installation terminated ${Font}"
                exit 2
                ;;
        esac
    fi

    do_uninstall_service_action

    create_overtls_systemd_service "${role}" "${local_bin_file_path}" "${local_cfg_file_path}"
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

function random_reverse_proxy_site() {
    local urls=(
        "https://www.sohu.com"
        "https://www.sina.com.cn"
        "https://www.baidu.com"
        "https://www.bilibili.com"
        "https://www.gov.cn"
        "https://www.jd.com"
        "https://www.taobao.com"
        "https://www.qq.com"
        "https://www.163.com"
        "https://www.douban.com"
        "https://www.zhihu.com"
        "https://www.toutiao.com"
        "http://www.xinhuanet.com"
        "https://www.cctv.com"
        "https://www.ifeng.com"
        "https://www.huanqiu.com"
        "https://www.people.com.cn"
        "http://www.news.cn"
        "https://www.chinanews.com"
        "https://chinaplus.cri.cn/"
        "https://www.chinadaily.com.cn"
    )
    local random_index=$((RANDOM % ${#urls[@]}))
    echo ${urls[$random_index]}
}

function caddy_web_server_config() {
    rm -rf ${caddy_conf_file}

    local selected_site=$(random_reverse_proxy_site)

    cat > ${caddy_conf_file} <<EOF
${web_svr_domain}:${web_svr_listen_port} {
    tls s@gmail.com
    encode gzip
    reverse_proxy /${reverse_proxy_location}/* ${web_svr_reverse_proxy_host}:${web_svr_reverse_proxy_port}
    reverse_proxy ${selected_site} {
        trusted_proxies 0.0.0.0/0
        header_up Host {upstream_hostport}
    }
}
EOF

    systemctl stop caddy
    sleep 2
    systemctl start caddy
    sleep 2
}

function print_qrcode() {
    local ot_exe_path="${1}"
    local ot_cfg_path="${2}"

    check_file_exists "${ot_exe_path}"
    check_file_exists "${ot_cfg_path}"

    local qrcode="$( ${ot_exe_path} -g -c ${ot_cfg_path} )"
    echo "${qrcode}"
    qrencode -t UTF8 "${qrcode}" | cat
}

function install_overtls_remote_server() {
    dependency_install

    web_svr_reverse_proxy_port=`random_listen_port`
    domain_check
    echo "请输入 站点端口号 (默认值 443) "
    web_svr_listen_port=`input_web_listen_port`

    do_uninstall_service_action

    install_caddy_in_debian
    caddy_web_server_config

    local svc_bin_path=$(download_n_install_overtls_server_bin)
    local cfg_path=$(write_overtls_config_file "${config_file_path}")

    if [ -f "${svc_bin_path}" ]; then
        create_overtls_systemd_service "server" "${svc_bin_path}" "${cfg_path}"
    else
        echo "${service_name} install failed, please contact the author!"
        exit 1
    fi

    cron_random_restart_overtls_svc

    echo
    echo "======== config.json ========"
    echo
    cat ${cfg_path}
    echo
    echo "============================="
    echo

    print_qrcode "${svc_bin_path}" "${cfg_path}"
}

function main() {
    echo
    echo "####################################################################"
    echo "# Script of Install ${service_name} Server"
    echo "# Author: ssrlive"
    echo "# Github: https://github.com/shadowsocksr-live/overtls"
    echo "####################################################################"
    echo

    local action=${1}
    [ -z ${1} ] && action="install"
    case "${action}" in
        install)
            check_root_account
            install_overtls_remote_server
            ;;
        uninstall)
            check_root_account
            uninstall_overtls
            ;;
        service)
            local role="${2}"
            local customer_binary_path="$3"
            local customer_cfg_file_path="$4"
            check_install_systemd_svc_params "${role}" "${customer_binary_path}" "${customer_cfg_file_path}"
            if [[ "$(uname)" == "Linux" ]]; then
                check_root_account
                install_binary_as_systemd_service "${role}" "${customer_binary_path}" "${customer_cfg_file_path}"
            elif [[ "$(uname)" == "Darwin" ]]; then
                macos_install_binary_as_service "${role}" "${customer_binary_path}" "${customer_cfg_file_path}"
            else
                echo -e "${RedBG} Unsupported operating system! ${Font}"
                exit 1
            fi
            ;;
        qrcode)
            local svc_bin_path="${2}"
            local cfg_path="${3}"
            if [[ "$(uname)" == "Darwin" ]]; then
                if ! command -v qrencode &> /dev/null ; then
                    if ! command -v brew &> /dev/null ; then
                        echo -e "${Info} ${Yellow} Homebrew not found, please install it first! ${Font}"
                        exit 1
                    fi
                    brew install qrencode >/dev/null 2>&1
                fi
            elif [[ "$(uname)" == "Linux" ]]; then
                sudo apt -y install qrencode >/dev/null 2>&1
            fi
            print_qrcode "${svc_bin_path}" "${cfg_path}"
            ;;
        *)
            echo "Arguments error! [${action}]"
            echo "Usage: `basename $0` [install|uninstall]"
            ;;
    esac

    exit 0
}

main "$@"

