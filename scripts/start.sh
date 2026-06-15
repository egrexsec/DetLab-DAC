#!/bin/bash
set -e

echo "Starting DetLab..."
docker compose up --build -d

echo ""
echo "DetLab is starting"
echo "Frontend: http://localhost:3000"
echo "API: http://localhost:8000"
