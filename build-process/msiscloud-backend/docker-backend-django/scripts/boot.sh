#!/bin/bash
set -e

set -x
echo "msiscloud-backend:boot:env:${APP_ENVIRONMENT}"

python manage.py makemigrations
python manage.py migrate
python manage.py collectstatic --noinput

if [ "$APP_ENVIRONMENT" == "Local" ]; then
  echo "msiscloud-backend:run:local"
  python manage.py runserver 0.0.0.0:8080 --insecure
elif [ "$APP_ENVIRONMENT" == "Production" ]; then
  echo "msiscloud-backend:run:prod"
  /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisor-backend.conf
fi
