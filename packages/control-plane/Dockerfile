FROM node:22-slim
WORKDIR /app
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm install better-sqlite3 tsx
COPY packages/control-plane ./packages/control-plane
EXPOSE 3000
ENV PORT=3000
CMD ["npx", "tsx", "packages/control-plane/src/index.ts"]
