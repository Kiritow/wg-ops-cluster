#/!bin/bash
docker-compose build && docker-compose up -d && docker-compose exec proxy nginx -s reload
