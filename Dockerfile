FROM node:26-alpine AS frontend
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.27.2-alpine AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kubegrant ./cmd/kubegrant

FROM scratch
COPY --from=backend /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=backend /out/kubegrant /kubegrant
COPY --from=frontend /src/web/dist/ /app/web/
ENV KUBEGRANT_HTTP_ADDR=:8080 KUBEGRANT_STATIC_DIR=/app/web KUBEGRANT_DATABASE_PATH=/data/kubegrant.db
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/kubegrant"]

