# syntax=docker/dockerfile:1.2

ARG PYTHON_VERSION=3.12

# Create the project image
FROM python:$PYTHON_VERSION

# Install extras packages
RUN apt-get update && apt-get install -y \
    gettext \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN python -m pip install --root-user-action=ignore -U uv

# Create a "developer" user, with sudo privileges (no password)
RUN useradd -ms /bin/bash developer && \
    echo "developer ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
USER developer

# Custom prompt to identify the container
RUN echo 'export PS1="\u@hidp-python:\w$ "' >> ~/.bashrc

# Make sure stdout is not buffered, in order to see output in real time
ENV PYTHONUNBUFFERED 1

# Require an active virtualenv for pip
ENV PIP_REQUIRE_VIRTUALENV true

# "activate" the virtualenv created by entrypoint.sh
ENV VIRTUAL_ENV /code/var/venv
ENV PATH $VIRTUAL_ENV/bin:$PATH

# Create .pgpass
RUN echo "*:*:*:postgres:postgres" > ~/.pgpass
RUN chmod 600 ~/.pgpass

# Make the uv cache survive container recreation
ENV UV_CACHE_DIR /code/var/cache/uv

# Make git trust the mounted repository, even when the permissions are "suspicious"
RUN git config --global --add safe.directory /code

WORKDIR /code/project
COPY entrypoint.sh .

ENTRYPOINT ["./entrypoint.sh"]
