FROM node:24-bookworm-slim
WORKDIR /app
COPY . .
RUN npm ci --omit=dev && npm run build
ENV NODE_ENV=production
ENV DSH_HOME=/data
RUN mkdir /data && chown node:node /data
USER node
EXPOSE 3081
CMD ["node", "--import", "tsx/esm", "src/dsh.ts", "--profile", "registry", "--host", "0.0.0.0", "--port", "3081"]
