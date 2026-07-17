#!/bin/bash

URL="http://localhost:8001/v1/ingest/jira"

echo "Esperando 2 segundos a que el contenedor SIEM estabilice..."
sleep 2

echo "=== Probando Endpoint /health ==="
curl -s -X GET "http://localhost:8001/health"
echo -e "\n"

echo "=== Enviando Webhook Simulado de Jira ==="
curl -s -X POST "$URL" \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": 1719154560,
    "webhookEvent": "jira:issue_updated",
    "issue": {
      "id": "10023",
      "key": "PROY-42",
      "fields": {
        "summary": "Error de conexion en base de datos de produccion",
        "description": "El pool de conexiones se agota tras picos de trafico inesperados.",
        "status": {
          "id": "3",
          "name": "In Progress"
        },
        "priority": {
          "id": "1",
          "name": "High"
        }
      }
    }
  }'

echo -e "\n=== Prueba Finalizada ==="
