FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

ARG APP_USER=cape
RUN groupadd -r ${APP_USER} && useradd --system --no-log-init -g ${APP_USER} -d /home/${APP_USER}/ -m ${APP_USER}

########################################################
# Install dependencies
########################################################
RUN apt update

RUN export LANGUAGE=en_US.UTF-8 && \
    export LANG=en_US.UTF-8 && \
    export LC_ALL=en_US.UTF-8

RUN apt install python3-pip -y
RUN apt install -y msitools \
    iptables \
    psmisc \ 
    jq \ 
    sqlite3 \ 
    tmux \
    net-tools \
    checkinstall \
    graphviz \
    python3-pydot \
    git \
    numactl \
    python3 \
    python3-dev \
    python3-pip \
    libjpeg-dev \
    zlib1g-dev

RUN apt install -y upx-ucl \
    libssl-dev \
    wget \
    zip \
    unzip \
    p7zip-full \
    lzip \
    rar \
    unrar \
    unace-nonfree \
    cabextract \
    geoip-database \
    libgeoip-dev \
    libjpeg-dev \
    mono-utils \
    ssdeep \
    libfuzzy-dev \
    exiftool

RUN apt install -y uthash-dev \
    libconfig-dev \
    libarchive-dev \
    libtool \
    autoconf \
    automake \
    privoxy \
    software-properties-common \
    wkhtmltopdf \
    xvfb \
    xfonts-100dpi \
    tcpdump \
    libcap2-bin

RUN apt install -y python3-pil \
    subversion \
    uwsgi \
    uwsgi-plugin-python3 \
    python3-pyelftools \
    curl \
    openvpn \
    wireguard 

RUN mkdir /tmp/capa && \
  git clone --recurse-submodules https://github.com/mandiant/capa.git /tmp/capa/ && \
  cd /tmp/capa && \
  ls /tmp/ && \
  git submodule update --init rules && \
  pip3 install .

RUN  apt install libre2-dev -y && \
   pip3 install cython && \
   pip3 install git+https://github.com/andreasvc/pyre2.git

RUN groupadd pcap && \
    usermod -a -G pcap ${APP_USER} && \
    chgrp pcap /usr/sbin/tcpdump && \
    setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

RUN apt install -y \
  binutils-dev \
  libldns-dev \
  libpcap-dev \
  libdate-simple-perl \
  libdatetime-perl \
  libdbd-mysql-perl

RUN cd /tmp && \
  git clone https://github.com/gamelinux/passivedns.git && \
  cd passivedns/ && \
  autoreconf --install && \
  ./configure && \
  make -j"$(getconf _NPROCESSORS_ONLN)" && \
  sudo checkinstall -D --pkgname=passivedns --default && \
  pip3 install unicorn capstone

########################################################
# Install Volatility3
########################################################
RUN apt install unzip && \
    pip3 install git+https://github.com/volatilityfoundation/volatility3 && \
    vol_path=$(python3 -c "import volatility3.plugins;print(volatility3.__file__.replace('__init__.py', 'symbols/'))") && \
    cd $vol_path && \
    wget https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip -O windows.zip  && \
    unzip windows.zip && \
    rm windows.zip && \
    chown "${APP_USER}:${APP_USER}" $vol_path -R

########################################################
# Install Suricata
########################################################

RUN add-apt-repository ppa:oisf/suricata-stable -y && \
    apt install suricata -y

RUN touch /etc/suricata/threshold.config && \
    pip3 install suricata-update && \
    mkdir -p "/etc/suricata/rules" 

RUN mkdir -p /etc/suricata/ && mkdir -p /etc/suricata/rules/ && mkdir -p /usr/share/suricata/rules/ && \
    /usr/bin/suricata-update --suricata /usr/bin/suricata --suricata-conf /etc/suricata/suricata.yaml -o /etc/suricata/rules/ && /usr/bin/suricatasc -c reload-rules /tmp/suricata-command.socket &>/dev/null
    #cp "/usr/share/suricata/rules/*" "/etc/suricata/rules/" && \
    #cp "/var/lib/suricata/rules/*" "/etc/suricata/rules/"
    
RUN sed -i 's|#default-rule-path: /etc/suricata/rules|default-rule-path: /etc/suricata/rules|g' /etc/default/suricata && \
  sed -i 's|default-rule-path: /var/lib/suricata/rules|default-rule-path: /etc/suricata/rules|g' /etc/suricata/suricata.yaml && \
  sed -i 's/#rule-files:/rule-files:/g' /etc/suricata/suricata.yaml && \
  sed -i 's/# - suricata.rules/ - suricata.rules/g' /etc/suricata/suricata.yaml && \
  sed -i 's/RUN=yes/RUN=no/g' /etc/default/suricata && \
  sed -i 's/mpm-algo: ac/mpm-algo: hs/g' /etc/suricata/suricata.yaml && \
  sed -i 's/mpm-algo: auto/mpm-algo: hs/g' /etc/suricata/suricata.yaml && \
  sed -i 's/#run-as:/run-as:/g' /etc/suricata/suricata.yaml && \
  sed -i "s/#  user: suri/   user: ${APP_USER}/g" /etc/suricata/suricata.yaml && \
  sed -i "s/#  group: suri/   group: ${APP_USER}/g" /etc/suricata/suricata.yaml && \
  sed -i 's/    depth: 1mb/    depth: 0/g' /etc/suricata/suricata.yaml && \
  sed -i 's/request-body-limit: 100kb/request-body-limit: 0/g' /etc/suricata/suricata.yaml && \
  sed -i 's/response-body-limit: 100kb/response-body-limit: 0/g' /etc/suricata/suricata.yaml && \
  sed -i 's/EXTERNAL_NET: "!$HOME_NET"/EXTERNAL_NET: "ANY"/g' /etc/suricata/suricata.yaml && \ 
  sed -i 's|#pid-file: /var/run/suricata.pid|pid-file: /tmp/suricata.pid|g' /etc/suricata/suricata.yaml && \
  sed -i 's|#ja3-fingerprints: auto|ja3-fingerprints: yes|g' /etc/suricata/suricata.yaml && \
  sed -i 's/#checksum-validation: none/checksum-validation: none/g' /etc/suricata/suricata.yaml && \
  sed -i 's/checksum-checks: auto/checksum-checks: no/g' /etc/suricata/suricata.yaml 

    # enable eve-log
RUN python3 -c "pa = '/etc/suricata/suricata.yaml';q=open(pa, 'rb').read().replace(b'eve-log:\n      enabled: no\n', b'eve-log:\n      enabled: yes\n');open(pa, 'wb').write(q);" && \
    python3 -c "pa = '/etc/suricata/suricata.yaml';q=open(pa, 'rb').read().replace(b'unix-command:\n  enabled: auto\n  #filename: custom.socket', b'unix-command:\n  enabled: yes\n  filename: /tmp/suricata-command.socket');open(pa, 'wb').write(q);" && \
    python3 -c "pa = '/etc/suricata/suricata.yaml';q=open(pa, 'rb').read().replace(b'file-store:\n  version: 2\n  enabled: no', b'file-store:\n  version: 2\n  enabled: yes');open(pa, 'wb').write(q);" && \
    chown ${APP_USER}:${APP_USER} -R /etc/suricata

########################################################
# Install YARA
########################################################

RUN apt install libtool libjansson-dev libmagic1 libmagic-dev jq autoconf -y

RUN  set -x && cd /tmp && \
    bash -c 'yara_info=$(curl -s https://api.github.com/repos/VirusTotal/yara/releases/latest)  && \
    yara_version=$(echo "$yara_info" |jq .tag_name|sed "s/\"//g")  && \
    echo "$yara_version" && \
    yara_repo_url=$(echo "$yara_info" | jq ".zipball_url" | sed "s/\"//g") && \ 
    wget -q "$yara_repo_url" && \ 
    unzip -q "$yara_version" && \ 
    directory=$(ls | grep "VirusTotal-yara-*") && \ 
    mkdir -p /tmp/yara_builded/DEBIAN && \ 
    cd "$directory" && \ 
    ./bootstrap.sh && \ 
    ./configure --enable-cuckoo --enable-magic --enable-dotnet --enable-profiling && \ 
    make -j"$(getconf _NPROCESSORS_ONLN)" && \ 
    yara_version_only=$(echo $yara_version|cut -c 2-) && \ 
    echo -e "Package: yara\nVersion: $yara_version_only\nArchitecture: $(dpkg --print-architecture)\nMaintainer: $MAINTAINER\nDescription: yara-$yara_version" > /tmp/yara_builded/DEBIAN/control && \ 
    make -j"$(nproc)" install DESTDIR=/tmp/yara_builded && \ 
    dpkg-deb --build --root-owner-group /tmp/yara_builded && \ 
    dpkg -i --force-overwrite /tmp/yara_builded.deb && \ 
    ldconfig'

RUN cd /tmp && \ 
    git clone --recursive https://github.com/VirusTotal/yara-python && \ 
    cd yara-python && \ 
    python3 setup.py build --enable-cuckoo --enable-magic --enable-dotnet --enable-profiling && \ 
    cd .. && \ 
    pip3 install ./yara-python

########################################################
# Install ClamAV
########################################################


RUN apt-get install clamav clamav-daemon clamav-freshclam clamav-unofficial-sigs -y 
RUN pip3 install -U pyclamd
COPY service_configs/00-clamav-unofficial-sigs.conf /usr/share/clamav-unofficial-sigs/conf.d/

RUN chown root:root /usr/share/clamav-unofficial-sigs/conf.d/00-clamav-unofficial-sigs.conf && \
    chmod 644 /usr/share/clamav-unofficial-sigs/conf.d/00-clamav-unofficial-sigs.conf && \
    usermod -a -G ${APP_USER} clamav 
RUN freshclam 
#RUN /usr/sbin/clamav-unofficial-sigs

########################################################
# Install Others
########################################################
ARG DIE_VERSION="3.04"
RUN apt install libqt5opengl5 libqt5script5 libqt5scripttools5 -y && \
    wget "https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_Ubuntu_$(lsb_release -rs)_amd64.deb" -O DIE.deb && \
    dpkg -i DIE.deb

RUN apt install -f checkinstall curl build-essential jq autoconf libjemalloc-dev -y

########################################################
# Install CAPE
########################################################
RUN cd /opt && \
    git clone https://github.com/kevoreilly/CAPEv2/ && \
    chown ${APP_USER}:${APP_USER} -R "/opt/CAPEv2/" && \
    CRYPTOGRAPHY_DONT_BUILD_RUST=1 pip3 install -r /opt/CAPEv2/requirements.txt && \
    pip3 install -r /opt/CAPEv2/requirements.github.txt

# RUN sed -i "/connection =/cconnection = postgresql://${USER}:${PASSWD}@localhost:5432/${USER}" /opt/CAPEv2/conf/cuckoo.conf && \
#     sed -i "/tor/{n;s/enabled = no/enabled = yes/g}" /opt/CAPEv2/conf/routing.conf && \
#     #sed -i "/memory_dump = off/cmemory_dump = on" /opt/CAPEv2/conf/cuckoo.conf
#     #sed -i "/machinery =/cmachinery = kvm" /opt/CAPEv2/conf/cuckoo.conf
#     sed -i "/interface =/cinterface = ${NETWORK_IFACE}" /opt/CAPEv2/conf/auxiliary.conf && \

RUN cd /opt/CAPEv2 && \
    python3 utils/community.py -waf -cr

########################################################
# Install Others - POST CAPE
########################################################
RUN set -x && cd /opt/CAPEv2/data/ && \
    apt install -y golang && \
    git clone https://github.com/x0r19x91/UnAutoIt && cd UnAutoIt && \
    GOOS="linux" GOARCH="amd64" go build -o UnAutoIt

RUN pip3 install git+https://github.com/DissectMalware/XLMMacroDeobfuscator.git
RUN pip3 install networkx>=2.1 graphviz>=0.8.4 pydot>=1.2.4

########################################################
# Install NGINX
########################################################
RUN apt install nginx -y
RUN ls /etc/nginx -l
RUN rm /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default
COPY service_configs/nginx.conf /etc/nginx/conf.d/default.conf
RUN nginx -t

########################################################
# Prep Container
########################################################

COPY conf /opt/CAPEv2/conf
COPY update_conf.py /update_conf.py
COPY docker-entrypoint.sh /entrypoint.sh


WORKDIR /opt/CAPEv2
VOLUME ["/opt/CAPEv2/conf"]
EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]

CMD ["/bin/bash", "/entrypoint.sh"]
