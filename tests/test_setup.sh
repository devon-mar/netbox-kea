#!/bin/bash

set -euxo pipefail

echo "Generating certs"
mkdir ./tests/files/certs/
openssl req -new -newkey rsa:2048 -sha256 -days 365 -nodes -x509 -keyout ./tests/files/certs/netbox.key -out ./tests/files/certs/netbox.crt -addext "subjectAltName=DNS:netbox" -subj "/CN=netbox"
openssl req -new -newkey rsa:2048 -sha256 -days 365 -nodes -x509 -keyout ./tests/files/certs/nginx.key -out ./tests/files/certs/nginx.crt -addext "subjectAltName=DNS:nginx" -subj "/CN=nginx"
chmod -R 0777 ./tests/files/certs/

echo "Copying docker-compose files"
cp -r ./tests/files/* ./netbox-docker/

echo "Copying whl"
WHL_FILE=$(ls ./dist/ | grep .whl)
cp  "./dist/$WHL_FILE" ./netbox-docker/

echo "::group::docker"

echo "Copying Dockerfile"
cp ./tests/files/Dockerfile ./

echo "Running docker-compose up"
cd netbox-docker
docker-compose build --build-arg "FROM=netboxcommunity/netbox:$NETBOX_CONTAINER_TAG" --build-arg "WHL_FILE=$WHL_FILE"
docker-compose up -d

echo "::endgroup::"
