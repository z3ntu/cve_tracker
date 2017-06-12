FROM python:alpine
MAINTAINER Luca Weiss <luca (at) z3ntu (dot) xyz>

ADD . /code
WORKDIR /code
RUN pip install -r requirements.txt

RUN apk update && apk upgrade && \
    apk add --no-cache git

EXPOSE 5000
CMD ["sh", "./run", "--host=0.0.0.0"]
