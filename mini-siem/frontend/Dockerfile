# frontend/Dockerfile
# Multi-stage build for Mini SIEM Frontend

# Development stage
FROM node:18-alpine as development

WORKDIR /app

# Copy package files
COPY frontend/package*.json ./

# Install dependencies
RUN npm install

# Copy application code
COPY frontend /app

# Expose port
EXPOSE 3000

# Start development server
CMD ["npm", "start"]

# Production build stage
FROM node:18-alpine as build

WORKDIR /app

COPY frontend/package*.json ./
RUN npm ci --only=production
COPY frontend /app
RUN npm run build

# Production serve stage
FROM nginx:alpine as production

COPY --from=build /app/build /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
