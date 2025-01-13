# Use an official Python runtime as a parent image
FROM python:3.12-slim-bookworm
ARG HASHANA_WHEEL=hashana-0.4.0-py3-none-any.whl

# Set the working directory in the container
WORKDIR /hashana

# Copy the requirements file into the container at /app
COPY requirements.txt requirements.txt
COPY zmq_server.py zmq_server.py
COPY $HASHANA_WHEEL $HASHANA_WHEEL

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -U -r requirements.txt
RUN rm requirements.txt
RUN pip install $HASHANA_WHEEL
RUN rm $HASHANA_WHEEL

ENV HASHANA_HOME=/hashana
ENV HASHANA_DB=/hashana/hashana.db
ENV HASHANA_PORT=5557

CMD ["python", "/hashana/zmq_server.py"]
