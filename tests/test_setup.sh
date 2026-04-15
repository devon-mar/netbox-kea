#!/bin/bash

set -euxo pipefail

echo "Generating certs"
mkdir ./tests/docker/certs/
openssl req -new -newkey rsa:2048 -sha256 -days 365 -nodes -x509 -keyout ./tests/docker/certs/ca.key -out ./tests/docker/certs/ca.crt -addext "basicConstraints=CA:true" -subj "/CN=Test CA"
openssl req -new -newkey rsa:2048 -sha256 -days 365 -nodes -x509 -CA ./tests/docker/certs/ca.crt -CAkey ./tests/docker/certs/ca.key -addext "basicConstraints=CA:false" -keyout ./tests/docker/certs/netbox.key -out ./tests/docker/certs/netbox.crt -addext "subjectAltName=DNS:netbox" -subj "/CN=netbox"
openssl req -new -newkey rsa:2048 -sha256 -days 365 -nodes -x509 -CA ./tests/docker/certs/ca.crt -CAkey ./tests/docker/certs/ca.key -addext "basicConstraints=CA:false" -keyout ./tests/docker/certs/dhcp6.key -out ./tests/docker/certs/dhcp6.crt -addext "subjectAltName=DNS:kea-dhcp6" -subj "/CN=kea-dhcp6"
openssl req -new -newkey rsa:2048 -sha256 -days 365 -nodes -x509 -CA ./tests/docker/certs/ca.crt -CAkey ./tests/docker/certs/ca.key -addext "basicConstraints=CA:false" -keyout ./tests/docker/certs/dhcp4.key -out ./tests/docker/certs/dhcp4.crt -addext "subjectAltName=DNS:kea-dhcp4" -subj "/CN=kea-dhcp4"
chmod -R 0777 ./tests/docker/certs/

echo "Copying whl"
WHL_FILE=$(ls ./dist/ | grep .whl)
cp  "./dist/$WHL_FILE" ./tests/docker/

echo "Running docker compose up"
cd ./tests/docker/
docker compose build --build-arg "FROM=netboxcommunity/netbox:$NETBOX_CONTAINER_TAG" --build-arg "WHL_FILE=$WHL_FILE"
docker compose up -d
