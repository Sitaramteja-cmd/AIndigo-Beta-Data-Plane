FROM node:22-slim
WORKDIR /app
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm install better-sqlite3 tsx
COPY packages/data-plane ./packages/data-plane
EXPOSE 8080
ENV PORT=8080
CMD ["sh", "-c", "npx tsx packages/data-plane/src/auto-sync.ts & npx tsx packages/data-plane/src/index.ts"]
