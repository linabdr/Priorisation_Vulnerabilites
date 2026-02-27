FROM node:24-slim

# Install python & cron
RUN apt-get update && apt-get install -y python3 python3-pip python3.11-venv cron 

# Create workdir
WORKDIR /app

# Copy python script
COPY collecteur_net.py /app/python/getCVE.py

#Create venv for python
RUN python3 -m venv /app/.venv

RUN /app/.venv/bin/python -m pip install --upgrade pip \
    && /app/.venv/bin/python -m pip install requests 

#Copy NextJs files
COPY prio_vuln/ /app/nextjs

WORKDIR /app/nextjs

RUN npm i

#CRON
COPY cronjob /etc/cron.d/cron_api-call
RUN chmod 644 /etc/cron.d/cron_api-call #exec perm
RUN crontab /etc/cron.d/cron_api-call #apply cron task

#Execution
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
CMD ["/app/entrypoint.sh"]

