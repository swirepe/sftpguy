# --- Stage 1: Build ---
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install git if needed for private modules
RUN apk add --no-cache git

# Copy and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the static binary
# CGO_ENABLED=0 is critical for scratch/distroless
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o sftp-server .

# --- Stage 2: Runtime ---
FROM gcr.io/distroless/static-debian12:latest

WORKDIR /

# Copy binary from builder
COPY --from=builder /app/sftp-server /sftp-server

# Create a directory for uploads and the DB
# (Distroless allows you to copy files, but we'll use a Volume)
# Use a non-root user (provided by distroless/static)
USER nonroot:nonroot

# Default ports and volumes
EXPOSE 2222
VOLUME ["/data"]

# Run the server
# Note: We point the DB and Dir to the /data volume
ENTRYPOINT ["/sftp-server"]
CMD ["-p", "2222", "-d", "/data/uploads", "-db", "/data/sftp.db", "-k", "/data/id_ed25519"]
