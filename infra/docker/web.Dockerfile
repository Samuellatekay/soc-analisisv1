FROM docker.io/library/node:22-alpine AS build
WORKDIR /w
COPY apps/web/package*.json ./
RUN npm ci
COPY apps/web .
RUN npm run build
FROM docker.io/nginxinc/nginx-unprivileged:1.27-alpine
COPY --from=build /w/dist /usr/share/nginx/html
COPY infra/docker/nginx.conf /etc/nginx/conf.d/default.conf
