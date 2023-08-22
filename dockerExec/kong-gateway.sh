#!/bin/bash

# Create DB
#docker run -d --name kong-database-http-virus-total \
#  --network=kong-net \
#  -p 5432:5432 \
#  -e "POSTGRES_USER=kong" \
#  -e "POSTGRES_DB=kong" \
#  -e "POSTGRES_PASSWORD=kongpass" \
#  postgres:13

# Migrate DB
#docker run --rm --network=kong-net \
# -e "KONG_DATABASE=postgres" \
# -e "KONG_PG_HOST=kong-database-http-virus-total" \
# -e "KONG_PG_PORT=5432" \
# -e "KONG_PG_PASSWORD=kongpass" \
# -e "KONG_PASSWORD=test" \
#kong/kong-gateway:3.4.0.0 kong migrations bootstrap

docker rm -f kong-gateway-http-virus-total

docker run -d --name kong-gateway-http-virus-total \
 --network=kong-net \
 --mount type=bind,source="$(pwd)"/kong/plugins/http-virus-total,destination=/usr/local/share/lua/5.1/kong/plugins/http-virus-total \
 -e "KONG_DATABASE=postgres" \
 -e "KONG_PG_HOST=kong-database-http-virus-total" \
 -e "KONG_PG_PORT=5432" \
 -e "KONG_PG_USER=kong" \
 -e "KONG_PG_PASSWORD=kongpass" \
 -e "KONG_PROXY_ACCESS_LOG=/dev/stdout" \
 -e "KONG_ADMIN_ACCESS_LOG=/dev/stdout" \
 -e "KONG_PROXY_ERROR_LOG=/dev/stderr" \
 -e "KONG_ADMIN_ERROR_LOG=/dev/stderr" \
 -e "KONG_PLUGINS=bundled,http-virus-total" \
 -e "KONG_NGINX_HTTP_CLIENT_BODY_BUFFER_SIZE=32M" \
 -e "KONG_ADMIN_LISTEN=0.0.0.0:8001" \
 -e "KONG_ADMIN_GUI_URL=http://localhost:8002" \
 -e KONG_LICENSE_DATA \
 -p 8000:8000 \
 -p 8443:8443 \
 -p 8001:8001 \
 -p 8444:8444 \
 -p 8002:8002 \
 -p 8445:8445 \
 -p 8003:8003 \
 -p 8004:8004 \
 kong/kong-gateway:3.4.0.0
 
 
 echo 'docker logs -f kong-gateway-http-virus-total'

 
 