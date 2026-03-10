FROM docker.io/node:24-bookworm
ENV NO_UPDATE_NOTIFIER=true
WORKDIR /opt/app-root/src
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build
EXPOSE 8080
CMD ["node", ".output/server/index.mjs"]
