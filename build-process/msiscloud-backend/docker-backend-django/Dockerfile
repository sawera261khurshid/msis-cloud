
# # Start from the Python image
# FROM python:3.12-slim

# # Set environment variables
# ENV PYTHONUNBUFFERED 1
# # ENV DJANGO_SETTINGS_MODULE=backend.settings
# ENV DJANGO_SETTINGS_MODULE=cloud_project.settings


# # Install dependencies
# RUN apt-get update && \
#     apt-get install -y --no-install-recommends \
#         git-core \
#         build-essential \
#         binutils \
#         libproj-dev \
#         gdal-bin \
#         supervisor \
#         python3-distutils && \
#     rm -rf /var/lib/apt/lists/*

# # Copy requirements
# COPY requirements /home/msiscloud-backend/requirements

# # Create media directory
# RUN mkdir -p /home/msiscloud-backend/media

# # Set the working directory
# WORKDIR /home/msiscloud-backend

# # Upgrade pip and install requirements
# RUN pip install --upgrade pip
# RUN pip install -r ./requirements/requirements.txt

# # Expose port 8080
# EXPOSE 8080

# # Create log directory
# RUN mkdir -p /var/logs/msiscloud

# # Copy scripts and configuration files
# COPY build-process/msiscloud-backend/docker-backend-django/scripts /home/docker/scripts
# COPY build-process/msiscloud-backend/docker-backend-django/config/supervisor-backend.conf /etc/supervisor/conf.d/supervisor-backend.conf

# # Modify boot.sh permissions and line endings
# RUN sed -i 's/\r$//' /home/docker/scripts/boot.sh && \
#     chmod +x /home/docker/scripts/boot.sh

# # Set the entry point to start the application
# ENTRYPOINT /home/docker/scripts/boot.sh

# # Copy the whole project to /home/msiscloud-backend
# COPY . /home/msiscloud-backend/



# Start from the Python image
FROM python:3.12-slim

# Set environment variables
ENV PYTHONUNBUFFERED 1
ENV DJANGO_SETTINGS_MODULE=cloud_project.settings

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git-core \
        build-essential \
        binutils \
        libproj-dev \
        gdal-bin \
        supervisor \
        python3-distutils && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /home/msiscloud-backend

# Copy requirements
COPY requirements /home/msiscloud-backend/requirements

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r /home/msiscloud-backend/requirements/requirements.txt

# Expose port 8080
EXPOSE 8080

# Create directories for logs and media files
RUN mkdir -p /var/logs/msiscloud /home/msiscloud-backend/media

# Copy configuration and scripts
COPY build-process/msiscloud-backend/docker-backend-django/scripts /home/docker/scripts
COPY build-process/msiscloud-backend/docker-backend-django/config/supervisor-backend.conf /etc/supervisor/conf.d/supervisor-backend.conf

# Modify boot.sh permissions and line endings
RUN sed -i 's/\r$//' /home/docker/scripts/boot.sh && \
    chmod +x /home/docker/scripts/boot.sh

# Copy the entire project to the container
COPY . /home/msiscloud-backend/

# Set the entry point to start the application
ENTRYPOINT ["/home/docker/scripts/boot.sh"]
