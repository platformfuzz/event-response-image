# Build stage
FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /event-response-app .

# Run stage
FROM alpine:3.19
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /event-response-app .
COPY web/ web/
ENV PORT=8080
EXPOSE 8080
CMD ["./event-response-app"]
