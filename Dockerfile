FROM astral/uv:python3.14-bookworm-slim


# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive

# Create working directory
WORKDIR /app

# Copy configuration files first (for better layer caching)
COPY pyproject.toml setup.py MANIFEST.in ./

# Copy the XSStrike package
COPY core ./core
COPY db ./db
COPY modes ./modes
COPY plugins ./plugins
COPY xsstrike.py ./

# Install everything using uv - reads pyproject.toml and installs package + dependencies + entry points
RUN uv run python setup.py install

# Add venv to PATH
ENV PATH="/app/.venv/bin:$PATH"

# Default working directory
WORKDIR /app

# run 4ever
ENTRYPOINT ["xsstrike"]

# Default command (shows help)
CMD ["-h"]