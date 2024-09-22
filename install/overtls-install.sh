#!/bin/bash

#==========================================================
#   System Request: Debian 7+ / Ubuntu 14.04+ / Centos 7+
#   Author: ssrlive
#   Dscription: overTLS onekey
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
            _binary_target="x86_64-unknown-linux-gnu"
            ;;
        aarch64)
            _binary_target="aarch64-unknown-linux-gnu"
            ;;
        armv7l)
            _binary_target="armv7-unknown-linux-gnueabihf"
            ;;
        *)
            echo -e "${Error} ${RedBG} The current CPU architecture ${CPU_ARCH} is not supported. Please contact the author! ${Font}"
            exit 1
            ;;
    esac
    echo ${_binary_target}
}

cpu_arch_target=$(get_binary_target)

overtls_install_sh="overtls-install.sh"
overtls_install_sh_url="https://raw.githubusercontent.com/shadowsocksr-live/overtls/master/install/overtls-install.sh"

overtls_bin_url="https://github.com/shadowsocksr-live/overtls/releases/latest/download/overtls-${cpu_arch_target}.zip"
overtls_bin_zip_file="overtls-${cpu_arch_target}.zip"

rust_setup_script_url="https://raw.githubusercontent.com/shadowsocksr-live/overtls/master/install/rust.sh"
rust_setup_script_file="rust.sh"

src_repo_url="https://github.com/shadowsocksr-live/overtls.git"

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
target_bin_path="/usr/bin/overtls-bin"
bin_name=overtls-bin

INSTALL_CMD="apt"

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

function is_glibc_ok() {
    glibc_version=$(ldd --version | awk '/ldd/{print $NF}')
    if [[ $(echo -e "$glibc_version\n2.18" | sort -V | head -n1) == "2.18" ]]; then
        echo -e "${OK} ${GreenBG} GLIBC version is ${glibc_version}, greater than or equal to 2.18, it's OK.${Font} " >&2
        return 0 # true
    else
        echo -e "${Info} ${Yellow} The current system GLIBC version is ${glibc_version}, which is less than 2.18, process must changed ${Font} " >&2
        return 1 # false
    fi
}

function script_file_full_path() {
    echo $(readlink -f "$0")
}

function is_git_repo() {
    repo_path="${1}"
    if [ -d "${repo_path}/.git" ]; then
        return 0 # 0 is true
    else
        return 1 # 1 is false
    fi
}

# Check if the script's two levels up directory is "overtls/install"
function is_script_located_in_source_tree() {
    local script_dir="$(dirname $(script_file_full_path))"

    parent_dir=$(dirname "$script_dir")  # Get the parent directory

    if [ "$(basename $parent_dir)/$(basename $script_dir)" = "overtls/install" ] && is_git_repo "${parent_dir}"; then
        return 0    # Return true if the path matches and is a git repo
    else
        return 1    # Return false if the path doesn't match or is not a git repo
    fi
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
        ${INSTALL_CMD} -y install crontabs
        ${INSTALL_CMD} -y install qrencode python3 make zlib zlib-devel gcc-c++ libtool openssl openssl-devel
    else
        ${INSTALL_CMD} install cron vim curl -y
        ${INSTALL_CMD} update -y
        ${INSTALL_CMD} install qrencode python3 cmake make zlib1g zlib1g-dev build-essential autoconf libtool openssl libssl-dev -y
        if [[ "${ID}" == "ubuntu" && `echo "${VERSION_ID}" | cut -d '.' -f1` -ge 20 ]]; then
            ${INSTALL_CMD} install inetutils-ping -y
        fi
    fi
    judge "Installing crontab"

    # New system does not require net-tools for IP determination.
    # ${INSTALL_CMD} install net-tools -y
    # judge "Installing net-tools"

    ${INSTALL_CMD} install bc -y
    judge "Installing bc"

    ${INSTALL_CMD} install unzip -y
    judge "Installing unzip"
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

function do_lets_encrypt_certificate_authority() {
    local org_pwd=`pwd`
    local renew=""

    mkdir -p ${site_cert_dir}
    cd ${site_cert_dir}

    if [ -f "./chained_cert.pem" ]; then
        echo -e "${Error} ${RedBG} A certificate already exists. Lets encrypt has maximum limit of 5 renewals per week. ${Font}"
        echo -e "${Error} ${RedBG} Do you want to delete it and create a new one? (y/n) ${Font}" && read renew
        case $renew in
            [yY][eE][sS]|[yY])
                echo -e "${GreenBG} Attempting to renew certificate ${Font}"
                sleep 2
                ;;
            *)
                echo -e "${GreenBG} Skipping certificate renewal ${Font}"
                cd ${org_pwd}
                return 0
                ;;
        esac
    fi
    rm -rf *

    openssl genrsa 4096 > account.key
    judge "[CA] Create account key"

    local openssl_cnf="/etc/ssl/openssl.cnf"
    if [[ "${ID}" == "centos" ]]; then
        openssl_cnf="/etc/pki/tls/openssl.cnf"
    fi

    openssl genrsa 4096 > private_key.pem
    openssl req -new -sha256 -key private_key.pem -subj "/" -reqexts SAN -config <(cat ${openssl_cnf} <(printf "[SAN]\nsubjectAltName=DNS:${web_svr_domain}")) > domain.csr
    judge "[CA] Create CSR file"

    curl -L https://raw.githubusercontent.com/diafygi/acme-tiny/master/acme_tiny.py -o acme_tiny.py
    python3 acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir ${site_dir}/.well-known/acme-challenge/ > ./signed.crt
    judge "[CA] Obtain website certificate"

    wget -O - https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem > intermediate.pem
    cat signed.crt intermediate.pem > chained_cert.pem
    judge "[CA] Merger of intermediate certificate and website certificate"

    wget -O - https://letsencrypt.org/certs/isrgrootx1.pem > root.pem
    cat intermediate.pem root.pem > full_chained_cert.pem
    judge "[CA] Root certificate and intermediate certificate merge"

    cd ${org_pwd}

    judge "[CA] Certificate configuration"
}

function acme_cron_update(){
    cat > ${site_cert_dir}/renew_cert.sh <<EOF
#!/bin/bash

cd ${site_cert_dir}
python3 acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir ${site_dir}/.well-known/acme-challenge/ > ./signed.crt || exit
wget -O - https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem > intermediate.pem
cat signed.crt intermediate.pem > chained_cert.pem
systemctl stop nginx
sleep 2
systemctl start nginx
sleep 2
EOF

    chmod a+x ${site_cert_dir}/renew_cert.sh

    local cron_name="cron"
    if [[ "${ID}" == "centos" ]]; then
        cron_name="crond"
    fi

    systemctl stop ${cron_name}
    sleep 2
    rm -rf tmp_info
    crontab -l > tmp_info
    echo "0 0 10 * * ${site_cert_dir}/renew_cert.sh >/dev/null 2>&1" >> tmp_info && crontab tmp_info && rm -rf tmp_info
    systemctl start ${cron_name}

    judge "cron scheduled task update"
}

function nginx_web_server_config_end() {
    rm -rf ${nginx_conf_file}
    cat > ${nginx_conf_file} <<EOF

    server {
        listen ${web_svr_listen_port} ssl default_server;
        listen [::]:${web_svr_listen_port} ssl default_server;
        ssl_certificate       ${site_cert_dir}/chained_cert.pem;
        ssl_certificate_key   ${site_cert_dir}/private_key.pem;
        ssl_protocols         TLSv1 TLSv1.1 TLSv1.2;
        ssl_ciphers           HIGH:!aNULL:!MD5;
        server_name           ${web_svr_domain};
        index index.php index.html index.htm index.nginx-debian.html;
        root  ${site_dir};
        error_page 400 = /400.html;

        location ~ \\.php$ {
            # include snippets/fastcgi-php.conf;
            # fastcgi_pass unix:/run/php/php8.3-fpm.sock;
        }

        location /${reverse_proxy_location}/ {
            proxy_redirect off;
            proxy_pass http://${web_svr_reverse_proxy_host}:${web_svr_reverse_proxy_port};
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$http_host;
        }
    }

    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name ${web_svr_domain};
        index index.php index.html index.htm index.nginx-debian.html;
        root  ${site_dir};

        location /.well-known/acme-challenge/ {
        }

        location / {
            # rewrite ^/(.*)$ https://${web_svr_domain}:${web_svr_listen_port}/$1 permanent;
        }
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

function build_overtls_server_bin() {
    local old_dir="$(pwd)"
    local work_dir=""
    if is_script_located_in_source_tree ; then
        echo -e "${OK} ${GreenBG} Building ${bin_name} from source tree ${Font}" >&2
        local script_dir="$(dirname $(script_file_full_path))"
        work_dir="$(dirname "${script_dir}")"
    else
        echo -e "${OK} ${GreenBG} Building ${bin_name} from github ${Font}" >&2
        work_dir="${old_dir}/overtls"
        if ! is_git_repo "${work_dir}" ; then
            rm -rf "${work_dir}"
            git clone "${src_repo_url}" overtls >&2
        fi
    fi

    local local_bin_path="${target_bin_path}"

    cd ${work_dir}

    cargo build --release >&2
    if [ $? -ne 0 ]; then echo "cargo build failed"; exit -1; fi

    rm -rf ${local_bin_path}
    local target_dir="$(dirname "${local_bin_path}")"
    cp target/release/${bin_name} ${target_dir}

    cd ${old_dir}

    echo "${local_bin_path}"
}

function write_overtls_config_file() {
    local local_cfg_file_path="${1}"
    local dir_path="$(dirname "${local_cfg_file_path}")"
    mkdir -p "${dir_path}"
    rm -rf "${local_cfg_file_path}"

    local hostname=$(echo $HOSTNAME)
    local identity=$(random_string_gen 4)

    cat > ${local_cfg_file_path} <<EOF
{
    "remarks": "${hostname}-${identity}",
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

    check_system

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

function macos_install_binary_as_service() {
    local role="${1}"
    local local_bin_file_path=${2}
    local local_cfg_file_path=${3}
    local svc_daemon_file_path="~/Library/LaunchAgents/${service_name}.plist"

    cat > ${svc_daemon_file_path} <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>${service_name}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>StartInterval</key>
    <integer>3</integer>
    <key>ProgramArguments</key>
    <array>
        <string>${local_bin_file_path}</string>
        <string>-r</string>
        <string>${role}</string>
        <string>-c</string>
        <string>${local_cfg_file_path}</string>
        <string>-d</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/usr/local</string>
  </dict>
</plist>
EOF

    launchctl load ${svc_daemon_file_path}
    launchctl start ${service_name}
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

function print_qrcode() {
    local ot_exe_path="${1}"
    local ot_cfg_path="${2}"

    check_file_exists "${ot_exe_path}"
    check_file_exists "${ot_cfg_path}"

    local qrcode="$( ${ot_exe_path} -g -c ${ot_cfg_path} )"
    echo "${qrcode}"
    qrencode -t UTF8 "${qrcode}" | cat
}

function rust_install() {
    local old_dir="$(pwd)"
    local work_dir="$(dirname $(script_file_full_path))"
    cd ${work_dir}

    if [ ! -f "./${rust_setup_script_file}" ]; then
        if ! curl -L ${rust_setup_script_url} -o ./${rust_setup_script_file} ; then
            echo -e "${RedBG} Failed to download ${rust_setup_script_file} script! ${Font}"
            exit 1
        fi
        chmod +x ./${rust_setup_script_file}
    fi

    ./${rust_setup_script_file}

    cd ${old_dir}
}

function install_overtls_remote_server() {
    is_glibc_ok
    if [ $? -ne 0 ]; then
        echo -e "${Info} ${Yellow} GLIBC version is too low, so we have to install rust and build ${service_name} from source code ${Font}"
        echo -e "${Info} ${Yellow} This will take a long time, please be patient ${Font}"
        rust_install
    fi
    check_system
    dependency_install

    web_svr_reverse_proxy_port=`random_listen_port`
    domain_check
    echo "请输入 站点端口号 (默认值 443) "
    web_svr_listen_port=`input_web_listen_port`

    do_uninstall_service_action

    nginx_install
    nginx_web_server_config_begin
    do_lets_encrypt_certificate_authority
    acme_cron_update
    nginx_web_server_config_end

    local svc_bin_path=""
    if is_glibc_ok ; then
        svc_bin_path=$(download_n_install_overtls_server_bin)
    else
        svc_bin_path=$(build_overtls_server_bin)
    fi
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
                check_system
                sudo ${INSTALL_CMD} -y install qrencode >/dev/null 2>&1
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

