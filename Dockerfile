FROM node:26-alpine@sha256:6f08a523443ddedf52941874c203475b0ad503e859ad70cb26ab8be9a517dbd5 AS frontend
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kubegrant ./cmd/kubegrant

FROM scratch
ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/Sushidesu486/KubeGrant" \
      org.opencontainers.image.revision="${SOURCE_REVISION}"
COPY --from=backend /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=backend /out/kubegrant /kubegrant
COPY --from=frontend /src/web/dist/ /app/web/
ENV KUBEGRANT_HTTP_ADDR=:8080 KUBEGRANT_STATIC_DIR=/app/web KUBEGRANT_DATABASE_PATH=/data/kubegrant.db
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/kubegrant"]
