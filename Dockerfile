FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/vuln-notes-api .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/vuln-notes-api /vuln-notes-api
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/vuln-notes-api"]
