#!/bin/bash
sfile="https://github.com/GawrAme/permaxui/raw/main"

colorized_echo() {
    local color=$1
    local text=$2
    
    case $color in
        "red")
        printf "\e[91m${text}\e[0m\n";;
        "green")
        printf "\e[92m${text}\e[0m\n";;
        "yellow")
        printf "\e[93m${text}\e[0m\n";;
        "blue")
        printf "\e[94m${text}\e[0m\n";;
        "magenta")
        printf "\e[95m${text}\e[0m\n";;
        "cyan")
        printf "\e[96m${text}\e[0m\n";;
        *)
            echo "${text}"
        ;;
    esac
}

colorized_echo green "=== 1. Checking OS is debian 12 or not ==="
# Pastikan script hanya berjalan di Debian 12 (Bookworm)
require_debian12() {
  # Sumber info OS standar
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
  fi

  # Deteksi nama cantik untuk pesan
  local pretty="${PRETTY_NAME:-$(uname -s) $(uname -r)}"

  # Cek ID harus 'debian'
  if [ "${ID:-}" != "debian" ]; then
    echo "[ERR] Script ini hanya untuk Debian 12 (Bookworm). Terdeteksi: ${pretty}" >&2
    return 1
  fi

  # Cek versi via os-release (utama)
  if [ -n "${VERSION_ID:-}" ]; then
    local major="${VERSION_ID%%.*}"
    if [ "$major" = "12" ]; then
      return 0
    fi
  fi

  # Fallback: cek codename via os-release
  if [ -n "${VERSION_CODENAME:-}" ] && [ "${VERSION_CODENAME}" = "bookworm" ]; then
    return 0
  fi

  # Fallback terakhir: /etc/debian_version
  if [ -r /etc/debian_version ]; then
    # contoh isi: "12.7" atau "bookworm/sid"
    local debver major
    debver="$(cat /etc/debian_version)"
    major="$(echo "$debver" | awk -F'[./ ]' '{print $1}')"
    if [ "$major" = "12" ]; then
      return 0
    fi
  fi

  colorized_echo red "[ERR] Script ini hanya untuk Debian 12 (Bookworm). Terdeteksi: ${pretty}" >&2
  return 1
}

if ! require_debian12; then
  exit 1
fi

DIR="/etc/x-ui"
mkdir -p /etc/x-ui

colorized_echo green "=== 2. Input Data ==="
read -rp "Masukkan Email anda: " email
read -rp "Masukkan Domain: " domain
echo "$domain" > $DIR/domain
domain=$(cat $DIR/domain)

colorized_echo green "=== 3. Updating Data ==="
clear
cd;
apt-get update;
apt-get install -y;

colorized_echo green "=== 4. Optimize Sysctl ==="
cat >/etc/sysctl.conf <<'SYSCTL'
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.eth0.send_redirects = 0
net.ipv4.conf.eth0.rp_filter = 0
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.rmem_default = 65536
net.core.wmem_default = 65536
net.ipv4.tcp_rmem = 4096 87380 8388608
net.ipv4.tcp_wmem = 4096 87380 8388608
net.ipv4.tcp_mem = 8388608 8388608 8388608
net.ipv4.route.flush = 1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syncookies = 1
net.core.somaxconn = 1024
kernel.sched_autogroup_enabled = 0
kernel.sched_migration_cost_ns = 5000000
SYSCTL

colorized_echo green "=== 5. Remove unused Module ==="
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;

colorized_echo green "=== 6. Installing benchmark module ==="
wget -q -O /usr/local/sbin/bench "https://raw.githubusercontent.com/teddysun/across/master/bench.sh" && chmod +x /usr/bin/bench

colorized_echo green "=== 6. Installing Toolkit ==="
apt-get install git libio-socket-inet6-perl libsocket6-perl libcrypt-ssleay-perl libnet-libidn-perl perl libio-socket-ssl-perl libwww-perl libpcre3 libpcre3-dev zlib1g-dev dbus iftop zip unzip wget net-tools curl nano sed screen gnupg gnupg1 bc apt-transport-https build-essential dirmngr dnsutils sudo at htop iptables bsdmainutils cron lsof lnav jq -y

colorized_echo green "=== 7. Installing lolcat & ruby ==="
apt-get install -y ruby;
gem install lolcat;

colorized_echo green "=== 8. Set time-zone to Jakarta [WIB] ==="
timedatectl set-timezone Asia/Jakarta;

colorized_echo green "=== 9. Installing 3X-UI ==="
printf 'y\n2053\n' | bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh) | tee /root/3xui-install.log

colorized_echo green "=== 10. Installing profile Module ==="
echo -e 'profile' >> /root/.profile
wget -O /usr/local/sbin/profile "$sfile/profile.sh";
chmod +x /usr/local/sbin/profile
apt install neofetch -y

colorized_echo green "=== 11. Installing VNStat ==="
apt -y install vnstat
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev
wget $sfile/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install 
cd
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
rm -f /root/vnstat-2.6.tar.gz 
rm -rf /root/vnstat-2.6

colorized_echo green "=== 12. Installing Speedtest Ookla ==="
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | sudo bash
sudo apt-get install speedtest -y

colorized_echo green "=== 13. Installing Gotop ==="
git clone --depth 1 https://github.com/cjbassi/gotop /tmp/gotop
/tmp/gotop/scripts/download.sh
cp /root/gotop /usr/bin/
chmod +x /usr/bin/gotop
cd

colorized_echo green "=== 14. Installing NGINX ==="
apt install nginx -y
mkdir -p /var/log/nginx
touch /var/log/nginx/access.log
touch /var/log/nginx/error.log
cat >/etc/nginx/nginx.conf <<'NGINX'
user  www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 4096;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;
    error_log   /var/log/nginx/error.log warn;

    sendfile        on;
    tcp_nopush      on;
    tcp_nodelay     on;
    keepalive_timeout  65;
    types_hash_max_size 2048;

    server_tokens off;
    client_max_body_size 20m;
    gzip on;
    gzip_types text/plain text/css application/json application/javascript application/xml image/svg+xml;

    include /etc/nginx/conf.d/*.conf;
}
NGINX
cat <<'NGINX1' | envsubst '${domain}' >/etc/nginx/conf.d/default.conf
server {
  listen       8081;
  server_name  ${domain};

  access_log /var/log/nginx/access.log;
  error_log  /var/log/nginx/error.log error;

  root   /var/www/html;
  index  index.html index.htm index.php;

  location / {
    try_files $uri $uri/ /index.php?$args;
  }

  location ~ \.php$ {
    include        /etc/nginx/fastcgi_params;
    # Gunakan salah satu: socket (umum di Debian/Ubuntu) ATAU TCP:9000
    # fastcgi_pass unix:/run/php/php-fpm.sock;
    fastcgi_pass  127.0.0.1:9000;

    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
  }
}
NGINX1
mkdir -p /var/www/html
systemctl stop nginx

colorized_echo green "=== 15. Installing Socat ==="
apt install iptables -y
apt install curl socat xz-utils wget apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release -y 
apt install socat cron bash-completion -y

colorized_echo green "=== 16. Installing Cert ==="
systemctl stop x-ui
curl https://get.acme.sh | sh -s email=$email
/root/.acme.sh/acme.sh --server letsencrypt --register-account -m $email --issue -d $domain --standalone -k ec-256 --debug
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/x-ui/xray.crt --keypath /etc/x-ui/xray.key --ecc

colorized_echo green "=== 17. Installing UFW Firewall ==="
apt install ufw -y
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw allow 2053/tcp
yes | sudo ufw enable
systemctl enable ufw
systemctl start ufw

colorized_echo green "=== 17. Installing Database & Config.json ==="
command -v sqlite3 >/dev/null 2>&1 || apt-get update -y && apt-get install -y sqlite3
wget -O /usr/local/x-ui/bin/config.json "$sfile/config.json"
wget -O /root/old.db "$sfile/old.db"
cp /etc/x-ui/x-ui.db /root/new.db
wget -O /root/migrate_xui.sql "$sfile/migrate_xui.sql"
cp /root/new.db "/root/new.db.bak.$(date +%F_%H%M%S)"
sqlite3 /root/new.db < /root/migrate_xui.sql
cp /root/new.db /etc/x-ui/x-ui.db
chown root:root /etc/x-ui/x-ui.db
chmod 600 /etc/x-ui/x-ui.db

colorized_echo green "=== FINISHING ==="
LOG=/root/3xui-install.log
CLEAN=/root/3xui-install.clean
OUT=/etc/x-ui
install -d -m 755 "$OUT"
# Bersihkan \r dan ANSI color codes
sed -r 's/\r//g; s/\x1B\[[0-9;]*[A-Za-z]//g' "$LOG" > "$CLEAN"
grep -E '^Username:[[:space:]]+'    "$CLEAN" | tail -1 | sed 's/^Username:[[:space:]]*//'    > "$OUT/username"
grep -E '^Password:[[:space:]]+'    "$CLEAN" | tail -1 | sed 's/^Password:[[:space:]]*//'    > "$OUT/password"
grep -E '^Port:[[:space:]]+'        "$CLEAN" | tail -1 | sed 's/^Port:[[:space:]]*//'        > "$OUT/api_port"
wb=$(grep -E '^WebBasePath:[[:space:]]+' "$CLEAN" | tail -1 | sed 's/^WebBasePath:[[:space:]]*//')
[[ "$wb" != /* ]] && wb="/$wb"; [[ "$wb" != */ ]] && wb="$wb/"
printf '%s' "$wb" > "$OUT/webbasepath"
grep -E '^Access URL:[[:space:]]+' "$CLEAN" | tail -1 | sed 's/^Access URL:[[:space:]]*//' > "$OUT/access_url"
chmod 600 "$OUT/username" "$OUT/password" "$OUT/webbasepath" "$OUT/api_port" "$OUT/access_url" 2>/dev/null
echo "Username:    $(cat "$OUT/username")"
echo "Password:    $(cat "$OUT/password")"
echo "API Port:    $(cat "$OUT/api_port")"
echo "WebBasePath: $(cat "$OUT/webbasepath")"
echo "Access URL:  $(cat "$OUT/access_url")"
neofetch
sed -i '/info title/d' ~/.config/neofetch/config.conf
sed -i '/info "Packages" packages/d' ~/.config/neofetch/config.conf
sed -i '/info "Shell" shell/d' ~/.config/neofetch/config.conf
sed -i '/info "Resolution" resolution/d' ~/.config/neofetch/config.conf
sed -i '/info "Memory" memory/d' ~/.config/neofetch/config.conf

#finishing
apt autoremove -y
apt clean
profile
systemctl restart x-ui
WEBPATH=$(cat /etc/x-ui/webbasepath)
USERNAME=$(cat /etc/x-ui/username)
PASSWORD=$(cat /etc/x-ui/password)
cat <<'NGINX2' | envsubst '${domain} ${WEBPATH}' >/etc/nginx/conf.d/xray.conf
server {
    listen 80;
    listen [::]:80;
    listen 443 ssl reuseport;
    listen [::]:443 ssl ipv6only=off reuseport;

    set_real_ip_from 127.0.0.0/8;
#ips-v4:
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 131.0.72.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
#ips-v6:
    set_real_ip_from 2400:cb00::/32;
    set_real_ip_from 2606:4700::/32;
    set_real_ip_from 2803:f800::/32;
    set_real_ip_from 2405:b500::/32;
    set_real_ip_from 2405:8100::/32;
    set_real_ip_from 2a06:98c0::/29;
    set_real_ip_from 2c0f:f248::/32;
    real_ip_header CF-Connecting-IP;
    real_ip_recursive on;
    #real_ip_header X-Forwarded-For;

    server_name ${domain};
    ssl_certificate     /etc/x-ui/xray.crt;
    ssl_certificate_key /etc/x-ui/xray.key;
    ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
    ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;

    root /var/www/html;

    # panel via prefix
    location ^~ ${WEBPATH} {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_pass http://127.0.0.1:2053;
    }

    location /sub {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_pass http://127.0.0.1:2096;
    }

    # === WS routes ===
    location ~ /buy-vpn-at-lingvpn/trojan-ws {
        if ($http_upgrade != "Upgrade") { rewrite /(.*) /buy-vpn-at-lingvpn/trojan-ws break; }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:1001;
        proxy_connect_timeout 4s;
        proxy_read_timeout 120s;
        proxy_send_timeout 12s;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
    }

    location ~ /buy-vpn-at-lingvpn/vmess-ws {
        if ($http_upgrade != "Upgrade") { rewrite /(.*) /buy-vpn-at-lingvpn/vmess-ws break; }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:2001;
        proxy_connect_timeout 4s;
        proxy_read_timeout 120s;
        proxy_send_timeout 12s;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
    }

    location ~ /buy-vpn-at-lingvpn/vless-ws {
        if ($http_upgrade != "Upgrade") { rewrite /(.*) /buy-vpn-at-lingvpn/vless-ws break; }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:3001;
        proxy_connect_timeout 4s;
        proxy_read_timeout 120s;
        proxy_send_timeout 12s;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
    }

    location ~ /buy-vpn-at-lingvpn/shadow-ws {
        if ($http_upgrade != "Upgrade") { rewrite /(.*) /buy-vpn-at-lingvpn/shadow-ws break; }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:4001;
        proxy_connect_timeout 4s;
        proxy_read_timeout 120s;
        proxy_send_timeout 12s;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
    }

    # === HTTPUpgrade routes (HU) ===
    location = /buy-vpn-at-lingvpn/trojan-hu {
        if ($http_upgrade != "websocket") { return 404; }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:1002;
        proxy_connect_timeout 4s;
        proxy_read_timeout 120s;
        proxy_send_timeout 12s;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location = /buy-vpn-at-lingvpn/vmess-hu {
        if ($http_upgrade != "websocket") { return 404; }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:2002;
        proxy_connect_timeout 4s;
        proxy_read_timeout 120s;
        proxy_send_timeout 12s;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location = /buy-vpn-at-lingvpn/vless-hu {
        if ($http_upgrade != "websocket") { return 404; }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:3002;
        proxy_connect_timeout 4s;
        proxy_read_timeout 120s;
        proxy_send_timeout 12s;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location = /buy-vpn-at-lingvpn/shadow-hu {
        if ($http_upgrade != "websocket") { return 404; }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:4002;
        proxy_connect_timeout 4s;
        proxy_read_timeout 120s;
        proxy_send_timeout 12s;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # === gRPC routes ===
    location ^~ /buy-vpn-at-lingvpn-trojan-grpc {
        if ($request_method != "POST") { return 404; }
        client_body_buffer_size 1m;
        client_body_timeout 1h;
        client_max_body_size 0;
        grpc_read_timeout 1h;
        grpc_send_timeout 1h;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_pass grpc://127.0.0.1:1003;
    }

    location ^~ /buy-vpn-at-lingvpn-vmess-grpc {
        if ($request_method != "POST") { return 404; }
        client_body_buffer_size 1m;
        client_body_timeout 1h;
        client_max_body_size 0;
        grpc_read_timeout 1h;
        grpc_send_timeout 1h;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_pass grpc://127.0.0.1:2003;
    }

    location ^~ /buy-vpn-at-lingvpn-vless-grpc {
        if ($request_method != "POST") { return 404; }
        client_body_buffer_size 1m;
        client_body_timeout 1h;
        client_max_body_size 0;
        grpc_read_timeout 1h;
        grpc_send_timeout 1h;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_pass grpc://127.0.0.1:3003;
    }

    location ^~ /buy-vpn-at-lingvpn-shadow-grpc {
        if ($request_method != "POST") { return 404; }
        client_body_buffer_size 1m;
        client_body_timeout 1h;
        client_max_body_size 0;
        grpc_read_timeout 1h;
        grpc_send_timeout 1h;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_pass grpc://127.0.0.1:4003;
    }
}
NGINX2
echo "Untuk data login dashboard 3XUI: "
echo "-=================================-"
echo "URL       : https://${domain}${WEBPATH}"
echo "username  : ${USERNAME}"
echo "password  : ${PASSWORD}"
echo "-=================================-"
echo "Script telah berhasil di install"
systemctl restart nginx
