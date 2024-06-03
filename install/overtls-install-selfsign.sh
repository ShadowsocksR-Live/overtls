#!/bin/bash

#==========================================================
#   System Request: Debian 7+ / Ubuntu 14.04+ / Centos 7+
#   Author: ssrlive
#   Description: overTLS onekey for musl building and self-signature
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

overtls_install_sh="overtls-install-selfsign.sh"
overtls_install_sh_url="https://raw.githubusercontent.com/shadowsocksr-live/overtls/master/install/overtls-install-selfsign.sh"

self_sign_script_url="https://raw.githubusercontent.com/shadowsocksr-live/overtls/master/install/selfsign.sh"
self_sign_script="selfsign.sh"
self_sign_dir="/overtls-selfsign"

overtls_bin_url="https://github.com/shadowsocksr-live/overtls/releases/latest/download/overtls-${cpu_arch_target}.zip"
overtls_bin_zip_file="overtls-${cpu_arch_target}.zip"

daemon_script_url="https://raw.githubusercontent.com/shadowsocksr-live/overtls/master/install/overtls-daemon.sh"
daemon_script_file="overtls-daemon.sh"
service_dir=/lib/systemd/system
service_name=overtls
service_stub=/etc/init.d/${service_name}

config_file_path="/etc/overtls/config.json"
nginx_conf_dir="/etc/nginx/conf.d"
nginx_conf_file="${nginx_conf_dir}/overtls.conf"
site_dir="/fakesite"
site_cert_dir="/fakesite_cert"
target_bin_path="/usr/local/bin/overtls"
bin_name=overtls

INSTALL_CMD="apt"

export web_svr_domain=""
export web_svr_local_ip_addr=""
export web_svr_reverse_proxy_host="0.0.0.0"
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

# Extract the English name of the distribution system from VERSION, in order to add the corresponding nginx apt source under debian / ubuntu
VERSION=`echo ${VERSION} | awk -F "[()]" '{print $2}'`

function check_system() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        echo -e "${OK} ${GreenBG} Current system is Centos ${VERSION_ID} ${VERSION} ${Font} "
        INSTALL_CMD="yum"
        echo -e "${OK} ${GreenBG} Please wait patiently during SElinux settings, do not perform other operations ${Font} "
        setsebool -P httpd_can_network_connect 1
        echo -e "${OK} ${GreenBG} SElinux setup complete ${Font} "
        ## Centos can also be installed by adding epel repositories, no changes are made currently
        cat>/etc/yum.repos.d/nginx.repo<<EOF
[nginx]
name=nginx repo
baseurl=http://nginx.org/packages/mainline/centos/7/\$basearch/
gpgcheck=0
enabled=1
EOF
        echo -e "${OK} ${GreenBG} nginx source installation complete ${Font}"
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "${OK} ${GreenBG} Current system is Debian ${VERSION_ID} ${VERSION} ${Font} "
        INSTALL_CMD="apt"
        ## Add nginx apt source
        if [ ! -f nginx_signing.key ]; then
            echo "deb http://nginx.org/packages/mainline/debian/ ${VERSION} nginx" >> /etc/apt/sources.list
            echo "deb-src http://nginx.org/packages/mainline/debian/ ${VERSION} nginx" >> /etc/apt/sources.list
            wget -nc https://nginx.org/keys/nginx_signing.key
            apt-key add nginx_signing.key
        fi
    elif [[ "${ID}" == "ubuntu" && `echo "${VERSION_ID}" | cut -d '.' -f1` -ge 16 ]]; then
        echo -e "${OK} ${GreenBG} Current system is Ubuntu ${VERSION_ID} ${VERSION_CODENAME} ${Font} "
        INSTALL_CMD="apt"
        ## Add nginx apt source
        if [ ! -f nginx_signing.key ]; then
            echo "deb http://nginx.org/packages/mainline/ubuntu/ ${VERSION_CODENAME} nginx" >> /etc/apt/sources.list
            echo "deb-src http://nginx.org/packages/mainline/ubuntu/ ${VERSION_CODENAME} nginx" >> /etc/apt/sources.list
            wget -nc https://nginx.org/keys/nginx_signing.key
            apt-key add nginx_signing.key
        fi
    elif [[ "${ID}" == "linuxmint" ]]; then
        INSTALL_CMD="apt"
    else
        echo -e "${Error} ${RedBG} Current system is ${ID} ${VERSION_ID} is not in the list of supported systems, installation is interrupted ${Font} "
        exit 1
    fi
}

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

function dependency_install() {
    ${INSTALL_CMD} install curl wget git lsof -y

    if [[ "${ID}" == "centos" ]]; then
        ${INSTALL_CMD} -y install crontabs bc unzip
        ${INSTALL_CMD} -y install libtool openssl openssl-devel
    else
        ${INSTALL_CMD} install cron bc unzip vim curl -y
        ${INSTALL_CMD} update -y
        ${INSTALL_CMD} install autoconf libtool openssl libssl-dev -y
        if [[ "${ID}" == "ubuntu" && `echo "${VERSION_ID}" | cut -d '.' -f1` -ge 20 ]]; then
            ${INSTALL_CMD} install inetutils-ping -y
        fi
    fi
    judge "Installing crontab"
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

function get_vps_valid_ip() {
    local web_svr_local_ip_v4_addr=`curl -4 ip.sb`
    local web_svr_local_ip_v6_addr=`curl -6 ip.sb`
    local ip_v4_regex='^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    local ip_v6_regex='^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$'
    if [[ $web_svr_local_ip_v4_addr =~ $ip_v4_regex ]]; then
        echo -e "${web_svr_local_ip_v4_addr}"
        return 0
    elif [[ $web_svr_local_ip_v6_addr =~ $ip_v6_regex ]]; then
        echo -e "${web_svr_local_ip_v6_addr}"
        return 0
    else
        echo "No valid IP found."
        return 1
    fi
}

function nginx_install() {
    if [[ -x /usr/sbin/nginx ]] && [[ -d /etc/nginx ]]; then
        echo -e "${OK} ${GreenBG} nginx has been installed before this moment ${Font}"
        return 0
    fi

    if [[ "${ID}" == "ubuntu" ]]; then
        ${INSTALL_CMD} install nginx-extras -y
    else
        ${INSTALL_CMD} install nginx -y
    fi

    if [[ -d /etc/nginx ]]; then
        echo -e "${OK} ${GreenBG} nginx installation is complete ${Font}"
        sleep 2
    else
        echo -e "${Error} ${RedBG} nginx installation failed ${Font}"
        exit 5
    fi

    systemctl enable nginx

    if [[ ! -f /etc/nginx/nginx.conf.bak ]]; then
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
        echo -e "${OK} ${GreenBG} nginx initial configuration backup completed ${Font}"
        sleep 1
    fi
}

function nginx_web_server_config_begin() {
    rm -rf /etc/nginx/sites-enabled/*

    rm -rf ${site_dir}
    mkdir -p ${site_dir}/.well-known/acme-challenge/
    chown -R www-data:www-data ${site_dir}
    chmod -R 777 ${site_dir}
    curl -L https://raw.githubusercontent.com/nginx/nginx/master/docs/html/index.html -o ${site_dir}/index.html
    curl -L https://raw.githubusercontent.com/nginx/nginx/master/docs/html/50x.html -o ${site_dir}/50x.html
    judge "[nginx] copy files"

    rm -rf ${nginx_conf_dir}/*
    cat > ${nginx_conf_file} <<EOF
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name localhost;
        index index.php index.html index.htm index.nginx-debian.html;
        root  ${site_dir};
    }
EOF

    systemctl stop nginx
    sleep 2
    systemctl start nginx
    sleep 2
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

    local hostname=$(echo $HOSTNAME)
    local short_hostname=${hostname:0:8}
    local identity=$(random_string_gen 4)
    local self_signed_cert_file="${self_sign_dir}/server.crt"
    local self_signed_key_file="${self_sign_dir}/server.key"
    local self_signed_root_ca_file="${self_sign_dir}/ca.crt"

    cat > ${local_cfg_file_path} <<EOF
{
    "remarks": "${short_hostname}-${identity}",
    "tunnel_path": "/${reverse_proxy_location}/",
    "test_timeout_secs": 5,

    "server_settings": {
        "certfile": "${self_signed_cert_file}",
        "keyfile": "${self_signed_key_file}",
        "forward_addr": "http://127.0.0.1:80",
        "listen_host": "${web_svr_reverse_proxy_host}",
        "listen_port": ${web_svr_reverse_proxy_port}
    },

    "client_settings": {
        "server_host": "${web_svr_local_ip_addr}",
        "server_port": ${web_svr_reverse_proxy_port},
        "server_domain": "${web_svr_domain}",
        "cafile": "${self_signed_root_ca_file}",
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

function create_self_signed_root_ca() {
    local old_dir=$(pwd)
    local work_dir="$(dirname $(script_file_full_path))"
    cd ${work_dir}

    if [ ! -f "./${self_sign_script}" ]; then
        if ! curl -L ${self_sign_script_url} -o ./${self_sign_script} ; then
            echo -e "${RedBG} Failed to download ${self_sign_script} script! ${Font}"
            exit 1
        fi
    fi

    local self_sign_script_path="${work_dir}/${self_sign_script}"

    mkdir -p "${self_sign_dir}"
    cd "${self_sign_dir}"

    local country="CN"
    local province=$(random_string_gen 5)
    local city=$(random_string_gen 7)
    local org=$(random_string_gen 10)
    local ca_common_name=$(random_string_gen 5)
    local server_common_name=$(random_string_gen 10)
    local email=$(random_string_gen 5)"@"${web_svr_domain}
    local domain=${web_svr_domain}
    local ip=${web_svr_local_ip_addr}
    bash ${self_sign_script_path} ${country} ${province} ${city} ${org} ${ca_common_name} ${server_common_name} ${email} ${domain} ${ip}

    cd ${old_dir}
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
    rm -rf ${service_stub}
    rm -rf ${target_bin_path}
    rm -rf ${service_dir}/${service_name}.service

    systemctl daemon-reload

    echo "${service_name} uninstall success!"
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
}

function install_overtls_remote_server() {
    check_system
    dependency_install

    web_svr_reverse_proxy_port=`random_listen_port`
    web_svr_domain=$(random_string_gen 10)".com"

    web_svr_local_ip_addr=$(get_vps_valid_ip)
    local exit_status=$?
    if [[ $exit_status -ne 0 ]]; then
        echo "No valid IP found."
        exit 1
    fi

    do_uninstall_service_action

    nginx_install
    nginx_web_server_config_begin

    create_self_signed_root_ca

    local svc_bin_path=$(download_n_install_overtls_server_bin)
    local cfg_path=$(write_overtls_config_file "${config_file_path}")

    if [ -f "${svc_bin_path}" ]; then
        create_overtls_systemd_service "server" "${svc_bin_path}" "${cfg_path}"
    else
        echo "${service_name} install failed, please contact the author!"
        exit 1
    fi

    echo
    echo "======== config.json ========"
    echo
    cat ${cfg_path}
    echo
    echo "============================="
    echo

    print_url "${svc_bin_path}" "${cfg_path}"
    echo
}

function main() {
    echo
    echo "####################################################################"
    echo "# Script of Install ${service_name} Server for musl building and self-signature"
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
        *)
            echo "Arguments error! [${action}]"
            echo "Usage: `basename $0` [install|uninstall]"
            ;;
    esac

    exit 0
}

main "$@"

