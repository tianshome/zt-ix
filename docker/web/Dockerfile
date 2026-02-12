FROM node:22.11.0-alpine AS build

WORKDIR /frontend

RUN npm install -g npm@11.10.0

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

FROM nginx:1.27.3-alpine

COPY docker/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY --from=build /frontend/dist /usr/share/nginx/html

EXPOSE 80
