FROM node:10.16

LABEL maintainer="Arkadi Shishlov <arkadi@agilestacks.com>"

RUN mkdir /app
WORKDIR /app

ENV NODE_ENV $NODE_ENV
COPY package.json package-lock.json /app/
RUN npm -q install --only=prod && npm -q cache clean --force
COPY server.js /app/
COPY src/ /app/src/

CMD [ "npm", "start" ]
