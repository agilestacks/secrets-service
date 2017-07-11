FROM node:7
MAINTAINER Arkadi Shishlov <arkadi@agilestacks.com>

RUN mkdir /app
WORKDIR /app

ENV NODE_ENV $NODE_ENV
COPY package.json npm-shrinkwrap.json /app/
RUN npm -q install --only=prod && npm -q cache clean
COPY server.js /app/
COPY src/ /app/src/

RUN npm link winston

CMD [ "npm", "start" ]
