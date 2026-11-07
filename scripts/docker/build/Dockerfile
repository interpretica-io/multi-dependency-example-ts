# Build environment
FROM debian:bookworm

ARG user
ARG uid
ARG gid
ARG docker_gid
ENV USER=${user}
ENV UID=${uid}
ENV GID=${gid}
ENV DOCKER_GID=${docker_gid}

RUN if [ "$DOCKER_GID" != "${GID}" ] && ! getent group ${DOCKER_GID} > /dev/null ; then groupadd --gid ${DOCKER_GID} docker ; fi

RUN if [ ! -d /home/${USER} ] ; then mkdir -p /home/${USER} && chmod -R 777 /home/${USER} ; fi 

# Install basic dependencies & useful tools
RUN apt-get update && \
    apt-get install -y \
        autoconf \
        automake \
        bison \
        build-essential \
        ccache \
        cmake \
        curl \
        docker.io \
        file \
        flex \
        gawk \
        libbsd-dev \
        libjansson-dev \
        libexpat1 \
        libexpat1-dev \
        libcurl4-openssl-dev \
        libglib2.0-dev \
        libnetconf2-dev \
        libncurses5 \
        libncurses5-dev \
        libpam0g \
        libpam0g-dev \
        libpcap0.8-dev \
        libpopt-dev \
        libreadline-dev \
        libssh-dev \
        libssh2-1-dev \
        libssl-dev \
        libusb-1.0-0 \
        libusb-1.0-0-dev \
        libxml2 \
        libxml2-dev \
        libxslt1-dev \
        libxslt1.1 \
        libpcre3-dev \
        libyaml-dev \
        m4 \
        meson \
        openssh-server \
        pkg-config \
        perl \
        python3 \
        python3-requests \
        python3-yaml \
        rsync \
        ssh \
        sudo \
        tshark \
        tcl-dev \
        wget

# --- The device under test: toolchains of the multi-dependency-example ---
# The example is five languages wired into a cycle; scripts/build-dut.sh
# builds a Linux copy of it inside this container so the agent runs real
# ELF binaries rather than the host's Mach-O ones.
RUN apt-get update && apt-get install -y \
        clang lld llvm python3-dev python3-pip \
        git jq file unzip xz-utils
ARG GO_VERSION=1.22.12
RUN curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz | \
        tar -C /usr/local -xz
ENV PATH=/usr/local/go/bin:/opt/cargo/bin:/opt/dotnet:${PATH}
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal \
        --default-toolchain stable && chmod -R a+rwX /opt/rustup /opt/cargo
ENV DOTNET_ROOT=/opt/dotnet DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1
RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
        && bash /tmp/dotnet-install.sh --channel 9.0 --install-dir /opt/dotnet \
        && chmod -R a+rX /opt/dotnet && rm /tmp/dotnet-install.sh

# --- The tools the tests drive on the agent ---
# None of the TAPIs installs what it drives; every one of them asks first
# (*_available / *_supports / tapi_package_installed) and the test skips
# when the answer is no. Installing them here turns those skips into runs.
ENV MDE_TOOL_PKGS="binutils elfutils lsof procps psmisc iproute2 \
    tcpdump openssl ca-certificates apt-utils"
# All at once when the archive has every package; one by one otherwise,
# so a package that is missing for this architecture costs its test a
# skip instead of costing the whole image.
RUN apt-get update && \
    ( apt-get install -y ${MDE_TOOL_PKGS} || \
      for p in ${MDE_TOOL_PKGS} ; do \
          apt-get install -y "$p" || echo "MDE: package $p unavailable" ; \
      done )

# Node.js 20 and Playwright with Chromium for tsf-playwright. The browsers
# go to a world-readable directory: the agent runs as the mounted user,
# not as root.
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright/browsers
RUN mkdir -p /opt/playwright && cd /opt/playwright && \
    npm init -y >/dev/null && npm install playwright@1.63.0 @playwright/test@1.63.0 && \
    npx playwright install --with-deps chromium && \
    chmod -R a+rX /opt/playwright
ENV NODE_PATH=/opt/playwright/node_modules

RUN echo "${USER} ALL=NOPASSWD: ALL" >> /etc/sudoers

RUN if [ "$DOCKER_GID" != "${GID}" ] && ! getent group ${GID} > /dev/null ; then groupadd --gid ${GID} ${USER} ; fi

RUN id -u ${USER} > /dev/null 2>&1 || useradd --system \
            --gid ${GID} --gid ${DOCKER_GID} \
            --uid ${UID} \
            --shell /bin/bash \
            ${USER}
# A base image's own system account of the same name (e.g. www-data) may
# already own ${USER}, with a home directory that is not writable by it;
# point it at the one made writable above instead.
RUN usermod -d /home/${USER} ${USER}
RUN usermod -a -G ${DOCKER_GID} ${USER}
RUN usermod -a -G docker ${USER}
