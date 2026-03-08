#!/bin/bash
cron -f & 
cd /app/nextjs
npm i
npm start  # Utilisez 'run dev' au lieu de 'start' pour le dev (hot reload)
wait

