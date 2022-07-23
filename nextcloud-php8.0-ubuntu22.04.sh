#!/bin/bash -e

HOME_DIR=/home/$SUDO_USER/
IPCONF=/etc/netplan/static.yaml

echo -e "\n\e[1;44mVerifications.\e[0m"
#Checking if script is launched with sudo/root
if [  "$USER" != "root" ]
then
echo -e "\e[1;31mCe script doit être executé en tant que root/sudo, arrêt du script.\e[0m"
exit
fi

#moving to user's directory
cd ${HOME_DIR}

if [ ! -f "$IPCONF" ]; then

#Static IPv4
read -p "Type STATIC IPv4 (xx.xx.xx.xx/yy): " staticip
read -p "Type GATEWAY ip : " gateway
read -p "Type DNS ip separated with a comma (xx.xx.xx.xx, yy.yy.yy.yy)  : " dnsservers
echo '
network:
  version: 2
  renderer: networkd
  ethernets:
    ens160:
      dhcp4: no
      dhcp6: no
      addresses:
        - '${staticip}'
      gateway4: '${gateway}'
      nameservers:
        addresses: ['${dnsservers}']
      routes:
        - to: '${gateway}'/32
          via: 0.0.0.0
          scope: link' > $IPCONF

mv /etc/netplan/00-installer-config.yaml /etc/netplan/00-installer-config.yaml.old
netplan apply
echo "System is gonna reboot to apply new network configuration"
sleep 10
reboot
fi

# update system 
echo -e "\e[1;34mUpdating the system.\e[0m"
apt update -q && apt upgrade -y -q
echo -e "\e[1;32mSystem updated.\e[0m"
echo ""

# install nginx, php, certbot, redis, mariaDB, ufw, unzip, fail2ban, portsentry
echo -e "\e[1;34mInstalling NGINX web server.\e[0m"
apt-get -y -q install nginx php-fpm php-cli php-json php-curl php-imap php-gd php-mysql php-xml php-zip php-intl php-imagick php-mbstring php-bcmath php-gmp software-properties-common certbot python3-certbot-nginx php-apcu redis-server php-redis mariadb-server mariadb-client ufw portsentry unzip fail2ban
echo -e "\e[1;32mInstallation done.\e[0m"
echo ""

# editing nginx.conf file
echo -e "\e[1;34mUpdtating nginx.conf file\e[0m"
PROCESSORS=$(grep processor /proc/cpuinfo | wc -l)

sed -i 's/worker_processes auto;/worker_processes '${PROCESSORS}';/g' /etc/nginx/nginx.conf
sed -i 's/# server_tokens off;/server_tokens off;/g' /etc/nginx/nginx.conf

echo -e "\e[1;32mNginx.conf file updated.\e[0m"
echo ""

# Creating web folder
echo -e "\e[1;34mCreating /home/www-data\e[0m"
mkdir /home/www-data/
chown -R ${USER}:www-data /home/www-data
chmod -R 770 /home/www-data
echo -e "\e[1;32mDone.\e[0m"
echo ""

#Installing Nextcloud
#Adding php 8.0
add-apt-repository ppa:ondrej/php
apt update && apt upgrade && apt install -y -q php8.0-fpm php8.0-common php8.0-mysql php8.0-xml php8.0-xmlrpc php8.0-curl php8.0-gd php8.0-imagick php8.0-cli php8.0-dev php8.0-imap php8.0-mbstring php8.0-opcache php8.0-soap php8.0-zip

wget https://download.nextcloud.com/server/releases/latest.tar.bz2
wget https://download.nextcloud.com/server/releases/latest.tar.bz2.sha256
wget https://download.nextcloud.com/server/releases/latest.tar.bz2.asc
wget https://nextcloud.com/nextcloud.asc

#check SHA256
echo -e "\e[1;34mChecking SHA256\e[0m"
sha256sum -c latest.tar.bz2.sha256 < latest.tar.bz2
read -n 1 -s -r -p "Press any key to confirm same SHA256."
echo ""

#check PGP signature
echo -e "\e[1;34mChecking PGP\e[0m"
gpg --import nextcloud.asc
gpg --verify latest.tar.bz2.asc latest.tar.bz2
read -n 1 -s -r -p "Press any key to confirm correct PGP signature."
echo ""

#Uncompressing Nextcloud
echo -e "\e[1;34mUncompressing nextcloud\e[0m"
tar -xvf latest.tar.bz2 -C /home/www-data/

#Cleaning useless files
echo -e "\e[1;34mRemoving compressed files\e[0m"
rm latest.tar.bz2* nextcloud.asc

#Adding Nextcloud User
echo -e "\e[1;34mAdding Nextcloud user\e[0m"
adduser nextcloud
adduser nextcloud www-data

#Setting Permissions
echo -e "\e[1;34mSetting permissions\e[0m"
chown -R nextcloud:www-data /home/www-data/nextcloud
chmod -R 770 /home/www-data


#Setting pm.max_children parameter for Nextcloud Pool
echo -e "\e[1;34mCalculating pm.max_children\e[0m"
systemctl stop php8.0-fpm.service
free -m
echo "-----------------------"
systemctl start php8.0-fpm.service && ps --no-headers -o "rss,cmd" -C php-fpm8.0 | awk '{ sum+=$1 } END { printf ("%d%s\n", sum/NR/1024,"M") }'
echo "-----------------------"
echo 'To set value, use this : '
echo 'RAM you wanna allocate / number above = pm.max_children value' 
echo 'example : 1024 / 18 = 56'
read -p "Set pm.max_children value to : " pmmaxchildren
echo ""

#Creating Nextcloud Pool
echo -e "\e[1;34mCreating nextcloud pool\e[0m"
echo '
[nextcloud]
listen = /var/run/nextcloud.sock

listen.owner = nextcloud
listen.group = www-data

user = nextcloud
group = www-data

pm = ondemand
pm.max_children = '${pmmaxchildren}'
pm.process_idle_timeout = 60s
pm.max_requests = 500

env[HOSTNAME] = $HOSTNAME
env[PATH] = /usr/local/bin:/usr/bin:/bin
env[TMP] = /tmp
env[TMPDIR] = /tmp
env[TEMP] = /tmp

request_terminate_timeout = 3600' >> /etc/php/8.0/fpm/pool.d/nextcloud.conf


#Editing php8.0-fpm service
echo -e "\e[1;34mUpdating php8.0-fpm\e[0m"
echo -e "\e[1;41mPlease paste this in php8.0-fpm service\e[0m"
echo -e "\e[41m[Service]
UMask=0027\e[0m"
read -n 1 -s -r -p "Press any key to continue."
echo ""
systemctl start php8.0-fpm.service
systemctl edit php8.0-fpm.service
systemctl reenable php8.0-fpm.service

#MariaDB configuration
echo -e "\e[1;34mMariaDB configuration\e[0m"
echo -e "\e[1;41mPlease use differents passwords for root and nextcloud user\e[0m"
read -n 1 -s -r -p "Press any key to continue."
echo ""
mysql_secure_installation


#Creating new database
echo -e "\e[1;34mCreating new database.\e[0m"
read -p "Nextcloud database name : " newnextclouddbname
read -p "Nextcloud database user : " newnextclouddbuser
echo -e "\e[1;41mPlease do not use the same password for nextcloud UNIX user and nextcloud SQL user\e[0m"
read -s -p "Nextcloud database user password : " newnextclouddbpasswd

mysql -u root -e "CREATE DATABASE IF NOT EXISTS ${newnextclouddbname} CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;"
echo -e "\e[1;32m${newnextclouddbname} database created.\e[0m"

mysql -u root -e "CREATE USER IF NOT EXISTS "${newnextclouddbuser}"@"localhost";"
echo -e "\e[1;32m${newnextclouddbuser} user created.\e[0m"

mysql -u root -e "SET password FOR "${newnextclouddbuser}"@"localhost" = password('${newnextclouddbpasswd}');"
echo -e "\e[1;32mPassword set.\e[0m"

mysql -u root -e "GRANT ALL PRIVILEGES ON ${newnextclouddbname}.* TO "${newnextclouddbuser}"@"localhost" IDENTIFIED BY '${newnextclouddbpasswd}';"
echo -e "\e[1;32mPermissions set.\e[0m"

mysql -u root -e "FLUSH PRIVILEGES;" 


#Virtual Host
echo -e "\e[1;34mCreating nginx virtual host file\e[0m"
read -p "Domain name for the nexcloud website : " nextclouddomain

echo "
upstream php-nextcloud {
    server                        unix:/var/run/nextcloud.sock;
}

server {
    listen                        80;
    listen                        [::]:80;
    server_name                   ${nextclouddomain};

    # Path to the root of your installation
    root                          /home/www-data/nextcloud/;

    # Add headers to serve security related headers
    add_header                    X-Frame-Options \"SAMEORIGIN\";
    add_header                    X-Content-Type-Options nosniff;
    add_header                    X-XSS-Protection \"1; mode=block\";
    add_header                    X-Robots-Tag none;
    add_header                    X-Download-Options noopen;
    add_header                    X-Permitted-Cross-Domain-Policies none;
    add_header                    Strict-Transport-Security 'max-age=31536000; includeSubDomains;';
    add_header                    Referrer-Policy no-referrer always;

    location = /robots.txt {
        allow                     all;
        log_not_found             off;
        access_log                off;
    }

    location = /.well-known/carddav {
      return                      301 \$scheme://\$host:\$server_port/remote.php/dav;
    }

    location = /.well-known/caldav {
      return                      301 \$scheme://\$host:\$server_port/remote.php/dav;
    }

    # set max upload size
    client_max_body_size          512M;
    fastcgi_buffers               64 4K;

    # Enable gzip but do not remove ETag headers
    gzip                          on;
    gzip_vary                     on;
    gzip_comp_level               4;
    gzip_min_length               256;
    gzip_proxied                  expired no-cache no-store private no_last_modified no_etag auth;
    gzip_types                    application/atom+xml application/javascript application/json application/ld+json application/manifest+json application/rss+xml application/vnd.geo+json application/vnd.ms-fontobject application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/bmp image/svg+xml image/x-icon text/cache-manifest text/css text/plain text/vcard text/vnd.rim.location.xloc text/vtt text/x-component text/x-cross-domain-policy;

    location / {
        rewrite                   ^ /index.php\$uri;
    }

    location ~ ^/.well-known/acme-challenge/* {
        allow                     all;
    }

    location ~ ^/(?:build|tests|config|lib|3rdparty|templates|data)/ {
        deny                      all;
    }

    location ~ ^/(?:\.|autotest|occ|issue|indie|db_|console) {
        deny                      all;
    }

    location ~ ^/(?:index|remote|public|cron|core/ajax/update|status|ocs/v[12]|updater/.+|ocs-provider/.+).php(?:$|/) {
        fastcgi_split_path_info   ^(.+.php)(/.*)$;
        include                   fastcgi_params;
        fastcgi_param             SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param             PATH_INFO \$fastcgi_path_info;
        fastcgi_param             HTTPS on;
        fastcgi_param             modHeadersAvailable true;
        fastcgi_param             front_controller_active true;
        fastcgi_pass              php-nextcloud;
        fastcgi_intercept_errors  on;
        fastcgi_request_buffering off;
        fastcgi_read_timeout      3600;
    }

    location ~ ^/(?:updater|ocs-provider)(?:$|/) {
        try_files                 \$uri/ =404;
        index                     index.php;
    }
    ssl_buffer_size               8k;
    ssl_stapling                  on;
    ssl_stapling_verify           on;

    # Adding the cache control header for js and css files
    # Make sure it is BELOW the PHP block
    location ~* .(?:css|js|woff|svg|gif)$ {
        try_files                 \$uri /index.php\$uri\$is_args\$args;
        add_header                Cache-Control \"public, max-age=15778463\";
        add_header                X-Content-Type-Options nosniff;
        add_header                X-XSS-Protection \"1; mode=block\";
        add_header                X-Robots-Tag none;
        add_header                X-Download-Options noopen;
        add_header                X-Permitted-Cross-Domain-Policies none;
        # Optional: Dont log access to assets
        access_log                off;
    }

    location ~* .(?:png|html|ttf|ico|jpg|jpeg)$ {
        try_files                 \$uri /index.php\$uri\$is_args\$args;
        # Optional: Dont log access to other assets
        access_log                off;
    }
}" >> /etc/nginx/sites-available/nextcloud.conf



#Enable virtual host
echo -e "\e[1;34mCreating nginx virtual host file\e[0m"
ln -s /etc/nginx/sites-available/nextcloud.conf /etc/nginx/sites-enabled/nextcloud.conf

#Generating SSL certs
echo -e "\e[1;34mCreating SSL certs\e[0m"
certbot --nginx

#Testing auto renew
echo -e "\e[1;34mTesting auto renew SSL certs\e[0m"
certbot renew --dry-run

#openssl dhparam -out /etc/ssl/certs/dhparam.pem 4096
#chmod 600 /etc/ssl/certs/dhparam.pem


#Updating virtual host
echo -e "\e[1;34mUpdating virtual host (http2)\e[0m"
sed -i 's/443 ssl/443 ssl http2/g' /etc/nginx/sites-available/nextcloud.conf

systemctl restart nginx.service
systemctl restart php8.0-fpm.service

echo -e "\e[41mGo at https://${nextclouddomain} and finish installation first.\e[0m"
read -n 1 -s -r -p "Once configuration is done, press any key to continue."
#Updating virtual host
echo -e "\e[1;34mUpdating virtual host (timeout)\e[0m"
sed -i '/fastcgi_read_timeout      3600;/d' /etc/nginx/sites-available/nextcloud.conf

#Updating php8.0-fpm
echo -e "\e[1;34mUpdating php8.0-fpm (timeout)\e[0m"
sed -i '/request_terminate_timeout = 3600/d' /etc/php/8.0/fpm/pool.d/nextcloud.conf


#Opcache
echo -e "\e[1;34mUpdating php8.0-fpm (opcache)\e[0m"
sed -i 's/;opcache.enable=1/opcache.enable=1/g' /etc/php/8.0/fpm/php.ini
sed -i 's/;opcache.enable_cli=0/opcache.enable_cli=1/g' /etc/php/8.0/fpm/php.ini
sed -i 's/;opcache.memory_consumption=128/opcache.memory_consumption=128/g' /etc/php/8.0/fpm/php.ini
sed -i 's/;opcache.interned_strings_buffer=8/opcache.interned_strings_buffer=32/g' /etc/php/8.0/fpm/php.ini
sed -i 's/;opcache.max_accelerated_files=10000/opcache.max_accelerated_files=10000/g' /etc/php/8.0/fpm/php.ini
sed -i 's/;opcache.revalidate_freq=2/opcache.revalidate_freq=1/g' /etc/php/8.0/fpm/php.ini
sed -i 's/;opcache.save_comments=1/opcache.save_comments=1/g' /etc/php/8.0/fpm/php.ini



#Adding APCu and redis
sed -i "s/'installed' => true,/'installed' => true,\n  'memcache.local' => '\\\OC\\\Memcache\\\APCu',\n  'memcache.locking' => '\\\OC\\\Memcache\\\Redis',\n  'redis' => array(\n    'host' => 'localhost',\n    'port' => 6379,\n  ),\nfail2ban/g" /home/www-data/nextcloud/config/config.php
echo "apc.enable_cli=1" >> /etc/php/8.0/mods-available/apcu.ini
systemctl restart php8.0-fpm.service

#Fail2Ban configuration
mkdir /var/log/nextcloud
chown nextcloud:nextcloud /var/log/nextcloud
sed -i "s/fail2ban/  'loglevel' => 2,\n  'logtimezone' => 'Europe\/Paris',\n  'logfile' => '\/var\/log\/nextcloud\/nextcloud.log',\n  'log_rotate_size' => '104857600'/g" /home/www-data/nextcloud/config/config.php

echo '
[Definition]
failregex=^{"reqId":".*","remoteAddr":".*","app":"core","message":"Login failed: ''.*'' \(Remote IP: ''<HOST>''\)","level":2,"time":".*"}$
          ^{"reqId":".*","level":2,"time":".*","remoteAddr":".*","user,:".*","app":"no app in context".*","method":".*","message":"Login failed: ''.*'' \(Remote IP: ''<HOST>''\)".*}$
          ^{"reqId":".*","level":2,"time":".*","remoteAddr":".*","user":".*","app":".*","method":".*","url":".*","message":"Login failed: .* \(Remote IP: <HOST>\).*}$' >> /etc/fail2ban/filter.d/nextcloud.conf


echo '
[DEFAULT]
ignoreip = 127.0.0.1/8
ignorecommand =
bantime  = 610
findtime = 600
maxretry = 3
backend = auto
usedns = warn
destemail = root@localhost
sendername = Fail2Ban
sender = fail2ban@localhost
banaction = iptables-multiport
mta = sendmail
protocol = tcp
action = %(action_mwl)s

[ssh]
enabled  = true
port  = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3

[pam-generic]
enabled  = true
filter   = pam-generic
port     = all
banaction = iptables-allports
logpath  = /var/log/auth.log
maxretry = 3

[xinetd-fail]
enabled   = true
filter    = xinetd-fail
port      = all
banaction = iptables-multiport-log
logpath   = /var/log/daemon.log
maxretry  = 2

[ssh-ddos]
enabled  = true
port  = ssh
filter   = sshd-ddos
logpath  = /var/log/auth.log
maxretry = 3

[ssh-route]
enabled = false
filter = sshd
action = route
logpath = /var/log/sshd.log
maxretry = 6

[ssh-iptables-ipset4]
enabled  = false
port  = ssh
filter   = sshd
banaction = iptables-ipset-proto4
logpath  = /var/log/sshd.log
maxretry = 6

[ssh-iptables-ipset6]
enabled  = false
port  = ssh
filter   = sshd
banaction = iptables-ipset-proto6
logpath  = /var/log/sshd.log
maxretry = 6

[php-url-fopen]
enabled = false
port    = http,https
filter  = php-url-fopen
logpath = /var/www/*/logs/access_log

[nginx-http-auth]
enabled = true
filter  = nginx-http-auth
port    = http,https
logpath = /var/log/nginx/error.log

[vsftpd]
enabled  = false
port     = ftp,ftp-data,ftps,ftps-data
filter   = vsftpd
logpath  = /var/log/vsftpd.log
maxretry = 6

[postfix]
enabled  = true
port     = smtp,ssmtp,submission
filter   = postfix
logpath  = /var/log/mail.log

[sasl]
enabled  = true
port     = smtp,ssmtp,submission,imap2,imap3,imaps,pop3,pop3s
filter   = postfix-sasl
logpath  = /var/log/mail.log

[dovecot]
enabled = true
port    = smtp,ssmtp,submission,imap2,imap3,imaps,pop3,pop3s
filter  = dovecot
logpath = /var/log/mail.log

[ssh-blocklist]
enabled  = false
filter   = sshd
action   = iptables[name=SSH, port=ssh, protocol=tcp]
           sendmail-whois[name=SSH, dest="%(destemail)s",\
           sender="%(sender)s", sendername="%(sendername)s"]
           blocklist_de[email="%(sender)s", apikey="xxxxxx",\
           service="%(filter)s"]
logpath  = /var/log/sshd.log
maxretry = 20

[nginx-404]
enabled  = true
filter   = nginx-404
action   = iptables-multiport[name=nginx-404, port="http,https", protocol=tcp]
logpath = /var/log/nginx*/*error*.log
maxretry = 2
findtime  = 6
bantime  = 1200

[nginx-auth]
enabled = true
filter = nginx-auth
action = iptables-multiport[name=NoAuthFailures, port="http,https"]
logpath = /var/log/nginx*/*error*.log
bantime = 630
maxretry = 3

[nginx-login]
enabled = true
filter = nginx-login
action = iptables-multiport[name=NoLoginFailures, port="http,https"]
logpath = /var/log/nginx*/*error*.log
bantime = 630
maxretry = 3

[nginx-badbots]
enabled  = true
filter = apache-badbots
action = iptables-multiport[name=BadBots, port="http,https"]
logpath = /var/log/nginx*/*error*.log
bantime  = 87000
maxretry = 1

[nginx-noscript]
enabled = true
action = iptables-multiport[name=NoScript, port="http,https"]
filter = nginx-noscript
logpath = /var/log/nginx*/*error*.log
maxretry = 6
bantime  = 87000

[nginx-proxy]
enabled = true
action = iptables-multiport[name=NoProxy, port="http,https"]
filter = nginx-proxy
logpath = /var/log/nginx*/*error*.log
maxretry = 0
bantime  = 87000

[nextcloud]
enabled = true
port = 80,443
protocol = tcp
filter = nextcloud
maxretry = 3
bantime = 3600
logpath = /var/log/nextcloud/nextcloud.log' >> /etc/fail2ban/jail.local

echo '
[Definition]
failregex = <HOST> - - [.*?] ".*?" 4(0[0-9]|1[0-5])
ignoreregex =' >> /etc/fail2ban/filter.d/nginx-404.conf

echo '
# Proxy filter /etc/fail2ban/filter.d/nginx-proxy.conf:
#
# Block IPs trying to use server as proxy.
#
# Matches e.g.
# 192.168.1.1 - - "GET http://www.something.com/
#
[Definition]
failregex = ^<HOST> -.*GET http.*
ignoreregex =' >> /etc/fail2ban/filter.d/nginx-proxy.conf

echo '
# Noscript filter /etc/fail2ban/filter.d/nginx-noscript.conf:
#
# Block IPs trying to execute scripts such as .php, .pl, .exe and other funny scripts.
#
# Matches e.g.
# 192.168.1.1 - - "GET /something.php
#
[Definition]
failregex = ^<HOST> -.*GET.*(\.php|\.asp|\.exe|\.pl|\.cgi|\scgi)
ignoreregex =' >> /etc/fail2ban/filter.d/nginx-noscript.conf

echo '
# Auth filter /etc/fail2ban/filter.d/nginx-auth.conf:
#
# Blocks IPs that fail to authenticate using basic authentication
#
[Definition]
failregex = no user/password was provided for basic \
authentication.*client: <HOST>
            user .* was not found in.*client: <HOST>
            user .* password mismatch.*client: <HOST>
ignoreregex =' >> /etc/fail2ban/filter.d/nginx-auth.conf

echo '
# Login filter /etc/fail2ban/filter.d/nginx-login.conf:
#
# Blocks IPs that fail to authenticate
# using web application''s log in page
#
# Scan access log for HTTP 200 + POST /sessions => failed log in
[Definition]
failregex = ^<HOST> -.*POST /sessions HTTP/1\.." 200
ignoreregex =' >> /etc/fail2ban/filter.d/nginx-login.conf

echo '
# Fail2Ban filter for postfix authentication failures
#

[INCLUDES]

before = common.conf

[Definition]

_daemon = postfix/smtpd

failregex = ^%(__prefix_line)swarning: [-._\w]+\[<HOST>\]: SASL (?:LOGIN|PLAIN|>

# Author: Yaroslav Halchenko' >> /etc/fail2ban/filter.d/postfix-sasl.conf

echo '
# Fail2Ban ssh filter for at attempted exploit
#
# The regex here also relates to a exploit:
#
#  http://www.securityfocus.com/bid/17958/exploit
#  The example code here shows the pushing of the exploit straight after
#  reading the server version. This is where the client version string normally
#  pushed. As such the server will read this unparsible information as
#  "Did not receive identification string".

[INCLUDES]

# Read common prefixes. If any customizations available -- read them from
# common.local
before = common.conf

[Definition]

_daemon = sshd

failregex = ^%(__prefix_line)sDid not receive identification string from <HOST>>

ignoreregex =

# Author: Yaroslav Halchenko' >> /etc/fail2ban/filter.d/sshd-ddos.conf

echo '#Postifix jail log' >> /var/log/mail.log
echo '#Xinetd-fail log' >> /var/log/daemon.log

systemctl restart fail2ban.service

#set php memory
sed -i 's/memory_limit = 128M/memory_limit = 512M/g' /etc/php/8.0/fpm/php.ini

chown -R www-data:www-data /home/www-data
chown -R nextcloud:www-data /home/www-data/nextcloud
systemctl restart php8.0-fpm.service

#patching database
-u nextcloud php8.0 /home/www-data/nextcloud/occ db:add-missing-indices
-u nextcloud php8.0 /home/www-data/nextcloud/occ db:convert-filecache-bigint

#portsentry configuration
sed -i 's/BLOCK_UDP="0"/BLOCK_UDP="1"/g' /etc/portsentry/portsentry.conf
sed -i 's/BLOCK_TCP="0"/BLOCK_TCP="1"/g' /etc/portsentry/portsentry.conf
sed -i 's/\/usr\/share\/doc\/portsentry\/examples\//\/usr\/share\/doc\/portsentry\/examples\/ \nKILL_RUN_CMD="\/sbin\/iptables -I INPUT -s $TARGET$ -j DROP \&\& \/sbin\/iptables -I INPUT -s $TARGET$ -m limit --limit 3\/minute --limit-burst 5 -j LOG --log-level debub --log-prefix ''Portsentry: dropping: ''"/g' /etc/portsentry/portsentry.conf
sed -i 's/TCP_MODE="tcp"/TCP_MODE="atcp"/g' /etc/default/portsentry
sed -i 's/UDP_MODE="udp"/UDP_MODE="audp"/g' /etc/default/portsentry
service portsentry restart

#updating SSH port
read -p "Please choose the new SSH port to listen (default 22) : " updatesshport
sed -i "s/#Port 22/Port ${updatesshport}/g" /etc/ssh/sshd_config
read -n 1 -s -r -p "Press any key to restart SSH service."
service ssh restart

#ufw config
ufw default deny
ufw allow 80
ufw allow 443
ufw allow ${updatesshport}
read -n 1 -s -r -p "Press any key to enable ufw."
ufw enable

#Upgrading SSL key from 1048 bits to 4096 bits
openssl dhparam -out /etc/ssl/certs/dhparam.pem 4096
chmod 600 /etc/ssl/certs/dhparam.pem
sed -i 's/ssl_dhparam \/etc\/letsencrypt\/ssl-dhparams.pem; # managed by Certbot/ssl_dhparam \/etc\/ssl\/certs\/dhparam.pem;/g'  /etc/nginx/sites-available/nextcloud.conf

#PhpMyAdmin Virtual Host
#apt install phpmyadmin
echo 'server {
        root /usr/share/phpmyadmin/;
        index index.html index.htm index.php ;
        server_name phpmyadmin.domain.org;

        location / {
            try_files $uri $uri/ =404;
        }

        # pass PHP scripts to FastCGI server
        #
        location ~ \.php$ {
               include snippets/fastcgi-php.conf;
        #
        #       # With php-fpm (or other unix sockets):
               fastcgi_pass unix:/var/run/php/php8.0-fpm.sock;
        #       # With php-cgi (or other tcp sockets):
        #       fastcgi_pass 127.0.0.1:9000;
        }' > ${HOME_DIR}/phpmyadmin.sample.config

