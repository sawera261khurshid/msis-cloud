
import os
from datetime import timedelta
import environ
# from decouple import config
# from distutils.util import strtobool

# Initialize environment variables
env = environ.Env()
environ.Env.read_env()  # Read .env file

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

APP_NAME = 'msis_app'

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env('SECRET_KEY', default="django-insecure-$$#u5h-*jiu_i6$k32x-fdbyx&7gn_9#tt#gjt)6-#vj$+niu2")  # Default for development

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = env.bool('DEBUG', default=False)  # Read DEBUG from environment, default is False
print(f'DEBUG={DEBUG}')

# ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=['127.0.0.1', 'localhost'])
ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=['127.0.0.1', 'localhost', 'localhost:8091'])


# MQTT connection settings
MQTT_BROKER_URL = env('MQTT_BROKER_URL', default='100.104.49.44')
# MQTT_BROKER_URL = env('MQTT_BROKER_URL', default='mqtt')  # Use service name 'mqtt'
MQTT_BROKER_PORT = env.int('MQTT_BROKER_PORT', default=1884)

# CORS settings
CORS_ALLOW_ALL_ORIGINS = env.bool('CORS_ALLOW_ALL_ORIGINS', default=True)
CORS_ALLOW_METHODS = [
    "GET", "POST", "PUT", "DELETE",
]
CORS_ALLOW_HEADERS = [
    "Content-Type", "authorization",
]
CORS_ALLOW_CREDENTIALS = True

# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    'rest_framework',
    'rest_framework_simplejwt',
    'drf_yasg',
    'whitenoise.runserver_nostatic',
    'corsheaders',
    APP_NAME,
    'mqtt_client',
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    'corsheaders.middleware.CorsMiddleware',
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    'whitenoise.middleware.WhiteNoiseMiddleware',
]

ROOT_URLCONF = "cloud_project.urls"
AUTH_USER_MODEL = 'msis_app.User'

# Database settings (PostgreSQL)
DATABASES = {
    "default": {
        # "ENGINE": "django.db.backends.postgresql_psycopg2",
        'ENGINE': 'django.db.backends.postgresql',
        "NAME": env('DATABASE_NAME', default='postgres'),
        "USER": env('DATABASE_USER', default='postgres'),
        "PASSWORD": env('DATABASE_PASSWORD', default='postgres'),
        "PORT": env.int('DATABASE_PORT', default=5432),
        "HOST": env('DATABASE_HOST', default='127.0.0.1'),
    }
}


# DATABASES = {
#     'default': {
#         # 'ENGINE': 'django.contrib.gis.db.backends.postgis',
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME':     config('DATABASE_NAME'),
#         'USER':     config('DATABASE_USER'),
#         'PASSWORD': config('DATABASE_PASSWORD'),
#         'HOST':     config('DATABASE_HOST'),
#         'PORT':     config('DATABASE_PORT'),
#     }
# }


# JWT settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=360),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
}

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]


SWAGGER_SETTINGS = {
    'SECURITY_DEFINITIONS': {
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header',
        }
    }
}

# Static files
STATIC_URL = '/static/'
STATIC_ROOT = env('STATIC_ROOT', default=os.path.join(BASE_DIR, 'staticfiles'))
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
]

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Localization
LANGUAGE_CODE = "en-us"
TIME_ZONE = 'Asia/Seoul'
USE_I18N = True
USE_TZ = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Logging settings
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {'format': '{levelname} {asctime} {module} {message}', 'style': '{'},
        'simple': {'format': '{levelname} {message}', 'style': '{'},
    },
    'handlers': {
        'console': {'class': 'logging.StreamHandler', 'formatter': 'verbose'},
    },
    'root': {'handlers': ['console'], 'level': 'DEBUG'},
    'loggers': {
        'django': {'handlers': ['console'], 'level': 'INFO', 'propagate': True},
        'mqtt_client': {'handlers': ['console'], 'level': 'DEBUG', 'propagate': False},
    },
}


# """
# Django settings for cloud_project project.
# """

# from pathlib import Path
# from datetime import timedelta
# import os
# from distutils.util import strtobool

# # Build paths inside the project like this: BASE_DIR / 'subdir'.
# BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# APP_NAME = 'msis_app'


# # SECURITY WARNING: keep the secret key used in production secret!
# SECRET_KEY = "django-insecure-$$#u5h-*jiu_i6$k32x-fdbyx&7gn_9#tt#gjt)6-#vj$+niu2"

# # SECURITY WARNING: don't run with debug turned on in production!
# DEBUG = strtobool(os.getenv('DEBUG', 'False'))  # Read DEBUG from environment as "DEBUG=True python3.10 manage.py ...", default is 'False'
# print(f'DEBUG={os.getenv("DEBUG", "False")}')


# ALLOWED_HOSTS = ['43.202.141.234', 'localhost', '127.0.0.1', 'ec2-43-202-141-234.ap-northeast-2.compute.amazonaws.com']

# # mqtt connection settings
# MQTT_BROKER_URL = "100.104.49.44"
# MQTT_BROKER_PORT = 1883

# # Allow All Origins (Development only)
# CORS_ALLOW_ALL_ORIGINS = True


# # Allow specific origins
# # CORS_ALLOWED_ORIGINS = [
# #     "http://localhost:3000",  # Your React frontend
# #     # "http://your-frontend-domain.com",  # Your production frontend domain
# #     # Add other domains as needed
# # ]

# CORS_ALLOW_METHODS = [
#     "GET",
#     "POST",
#     "PUT",
#     # "PATCH",
#     "DELETE",
#     # "OPTIONS",
# ]

# CORS_ALLOW_HEADERS = [
#     "Content-Type",
#     "authorization",
#     # Add other headers as needed
# ]


# # Allow credentials (Cookies , HTTP Auth)
# CORS_ALLOW_CREDENTIALS = True


# # Application definition
# INSTALLED_APPS = [
#     "django.contrib.admin",
#     "django.contrib.auth",
#     "django.contrib.contenttypes",
#     "django.contrib.sessions",
#     "django.contrib.messages",
#     "django.contrib.staticfiles",
#     'rest_framework',
#     'rest_framework_simplejwt',
#     'drf_yasg',
#     'whitenoise.runserver_nostatic', #zubair edits
#     'corsheaders',
#     APP_NAME,
#     'mqtt_client',
# ]

# MIDDLEWARE = [
#     "django.middleware.security.SecurityMiddleware",
#     "django.contrib.sessions.middleware.SessionMiddleware",
#         'corsheaders.middleware.CorsMiddleware',
#     "django.middleware.common.CommonMiddleware",
#     "django.middleware.csrf.CsrfViewMiddleware",
#     "django.contrib.auth.middleware.AuthenticationMiddleware",
#     "django.contrib.messages.middleware.MessageMiddleware",
#     "django.middleware.clickjacking.XFrameOptionsMiddleware",
#     'whitenoise.middleware.WhiteNoiseMiddleware', #zubair edits
# ]

# ROOT_URLCONF = "cloud_project.urls"


# AUTH_USER_MODEL = 'msis_app.User'




# TEMPLATES = [
#     {
#         "BACKEND": "django.template.backends.django.DjangoTemplates",
#         "DIRS": [],
#         "APP_DIRS": True,
#         "OPTIONS": {
#             "context_processors": [
#                 "django.template.context_processors.debug",
#                 "django.template.context_processors.request",
#                 "django.contrib.auth.context_processors.auth",
#                 "django.contrib.messages.context_processors.messages",
#             ],
#         },
#     },
# ]

# WSGI_APPLICATION = "cloud_project.wsgi.application"


# # # postgresql
# # DATABASES = {
# #     "default": {
# #         "ENGINE":       "django.db.backends.postgresql_psycopg2",
# #         "NAME":         "msiscloud_db",
# #         "USER":         "postgres",
# #         "PASSWORD":     "msis2024cloud*&",
# #         "PORT":         "5432",
# #         "HOST":         "ec2-43-202-141-234.ap-northeast-2.compute.amazonaws.com",
# #     }
# # }

# DATABASES = {
#     "default": {
#         "ENGINE":       "django.db.backends.postgresql_psycopg2",
#         "NAME":         "msis-cloud",
#         "USER":         "postgres",
#         "PASSWORD":     "admin",
#         "PORT":         "5432",
#         "HOST":         "localhost",
#     }
# }

# # SQLite
# # DATABASES = {
# #     'default': {
# #         'ENGINE': 'django.db.backends.sqlite3',
# #         'NAME': BASE_DIR / 'db.sqlite3',
# #     }
# # }

# REST_FRAMEWORK = {
#     'DEFAULT_SCHEMA_CLASS': 'rest_framework.schemas.coreapi.AutoSchema',
#     'DEFAULT_AUTHENTICATION_CLASSES': [
#         'rest_framework_simplejwt.authentication.JWTAuthentication',
#     ],
    
#     'DEFAULT_PERMISSION_CLASSES': [
#         'rest_framework.permissions.IsAuthenticated',
#     ],
#     'APPEND_SLASH': False,
# }

# CACHES = {
#     'default': {
#         'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
#         'LOCATION': 'unique-snowflake',
#     }
# }

# AUTHENTICATION_BACKENDS = [
#     'msis_app.backends.CustomBackend',
#     'django.contrib.auth.backends.ModelBackend',  # Keep this if you also want to allow username authentication
# ]

# SIMPLE_JWT = {
#     'ACCESS_TOKEN_LIFETIME': timedelta(minutes=360),  # Set access token lifetime
#     'REFRESH_TOKEN_LIFETIME': timedelta(days=1),  # Set refresh token lifetime
#     'ROTATE_REFRESH_TOKENS': True,  # Optional: rotate refresh tokens
#     'BLACKLIST_AFTER_ROTATION': True,  # Optional: blacklist old refresh tokens
# }

# SWAGGER_SETTINGS = {
#     'SECURITY_DEFINITIONS': {
#         'Bearer': {
#             'type': 'apiKey',
#             'name': 'Authorization',
#             'in': 'header',
#         }
#     }
# }


# # Password validation
# # https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

# AUTH_PASSWORD_VALIDATORS = [
#     {
#         "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
#     },
#     {
#         "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
#     },
#     {
#         "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
#     },
#     {
#         "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
#     },
# ]



# # Internationalization
# # https://docs.djangoproject.com/en/5.0/topics/i18n/

# LANGUAGE_CODE = "en-us"
# # TIME_ZONE = "UTC"
# TIME_ZONE = 'Asia/Seoul'
# USE_I18N = True
# USE_TZ = True


# # Static files (CSS, JavaScript, Images)
# # https://docs.djangoproject.com/en/5.0/howto/static-files/

# ###### Zubair Edits
# STATIC_URL = '/static/'
# STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')  # Final directory for collected static files
# STATICFILES_DIRS = [
#     os.path.join(BASE_DIR, 'static'),  # Only the custom static folder, if you have one
#     # Do not include STATIC_ROOT here
# ]

# DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# LOGGING = {
#     'version': 1,
#     'disable_existing_loggers': False,
#     'formatters': {
#         'verbose': {
#             'format': '{levelname} {asctime} {module} {message}',
#             'style': '{',
#         },
#         'simple': {
#             'format': '{levelname} {message}',
#             'style': '{',
#         },
#     },
#     'handlers': {
#         'console': {
#             'class': 'logging.StreamHandler',
#             'formatter': 'verbose',
#         },
#     },
#     'root': {
#         'handlers': ['console'],
#         'level': 'DEBUG',
#     },
#     'loggers': {
#         'django': {
#             'handlers': ['console'],
#             'level': 'INFO',
#             'propagate': True,
#         },
#         'mqtt_client': {  # logger for mqtt_client app
#             'handlers': ['console'],
#             'level': 'DEBUG',
#             'propagate': False,
#         },
#     },
# }

