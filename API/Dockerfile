FROM python:3.13


WORKDIR /opt

# Add Poetry to PATH
ENV POETRY_HOME=/opt/poetry
ENV POETRY_VIRTUALENVS_CREATE False
ENV PATH="$POETRY_HOME/bin:$PATH"

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python -

# Copy Poetry configuration files
COPY poetry.lock pyproject.toml ./

# Install dependencies (runtime only)
RUN poetry install --only main --no-interaction --no-root

COPY ./app /opt/app

RUN chmod -R +x /opt/app

WORKDIR /opt/app

CMD ["uvicorn", "--reload", "--host=0.0.0.0", "--port=8000", "main:app"]
