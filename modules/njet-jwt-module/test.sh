#!/usr/bin/env bash
JWT=`curl -X POST 192.168.40.206:8080/jwt/10 -H 'Content-Type: application/json'  -d  '{"name":"cx"}' -v | jq -r .token`
curl -X GET localhost:1080/jwt/demo -H "Authorization:Bearer $JWT" -v