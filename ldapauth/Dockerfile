<<<<<<< HEAD
ARG BUILD_FROM=ghcr.io/home-assistant/base:3.24
FROM $BUILD_FROM

RUN apk add --no-cache python3 py3-pip \
    && python3 -m venv /opt/venv
COPY requirements.txt /tmp/requirements.txt
RUN /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt \
    && /opt/venv/bin/pip uninstall --yes pip \
    && apk del py3-pip \
    && rm /tmp/requirements.txt

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt
COPY *.py LICENSE NOTICE /opt/ldapauth/
COPY static /opt/ldapauth/static
COPY rootfs /
RUN chmod 0755 /etc/s6-overlay/s6-rc.d/ldapauth/run

ARG BUILD_VERSION=3.0.0
LABEL io.hass.type="addon" \
    org.opencontainers.image.licenses="Apache-2.0" \
    io.hass.name="Active Directory Authentication" \
    io.hass.version="${BUILD_VERSION}" \
    org.opencontainers.image.title="Active Directory Authentication" \
    org.opencontainers.image.source="https://github.com/janlon6260/home-assistant-active-directory-auth"
=======
FROM ghcr.io/home-assistant/base:3.24

RUN apk add --no-cache python3 py3-pip py3-flask py3-ldap3 jq openssl

COPY ldap_server.py /usr/bin/ldap_server.py
RUN chmod +x /usr/bin/ldap_server.py

COPY rootfs /
>>>>>>> 84ff87661257a50a6147736f22ecdd92426dff54
