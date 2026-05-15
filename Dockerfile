# Стабильная версия R (Ubuntu 22.04 Jammy) — совпадает с Posit PM в CI/CD
FROM rocker/r-ver:4.3.2

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    wget \
    libcurl4-openssl-dev \
    libssl-dev \
    libxml2-dev \
    cmake \
    bash \
    && rm -rf /var/lib/apt/lists/*

RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
      | tee /etc/apt/sources.list.d/security:zeek.list \
    && curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
      | gpg --dearmor \
      | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

RUN apt-get update && apt-get install -y \
    zeek \
    zeek-aux \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/zeek/bin:${PATH}"
ENV ZEEK_BIN=/opt/zeek/bin/zeek

WORKDIR /app

# Слой зависимостей кэшируется, пока не меняется DESCRIPTION
ARG INSTALL_SUGGESTS=true
ENV INSTALL_SUGGESTS=${INSTALL_SUGGESTS}
ENV RSPM=https://packagemanager.posit.co/cran/__linux__/jammy/latest

COPY DESCRIPTION install_dependencies.R /app/
RUN Rscript install_dependencies.R

COPY . /app/

EXPOSE 4321
