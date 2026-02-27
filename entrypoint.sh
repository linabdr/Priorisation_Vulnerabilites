#!/bin/bash
cron -f & 
cd /app/nextjs && npm run dev  # Utilisez 'start' pour la production
wait

