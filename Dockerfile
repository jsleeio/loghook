# Start by building the application.
FROM golang:1.10 as build

WORKDIR /go/src/github.com/jsleeio/loghook
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build

# Now copy it into our base image.
FROM scratch
COPY --from=build /go/src/github.com/jsleeio/loghook/loghook /loghook
USER 1000
ENV LOGHOOK_GITHUB_WEBHOOK_SECRET "configure_me"
ENTRYPOINT ["/loghook"]
