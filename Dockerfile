# Start by building the application.
FROM golang:1.12 AS build
RUN \
  adduser \
    --home=/build \
    --disabled-password \
    --uid 1000 \
    --gecos 'Golang build' \
    build
ADD . /build/src
RUN chown -R build /build
USER build
WORKDIR /build/src
RUN mkdir /build/go
RUN GOCACHE=/build/go CGO_ENABLED=0 GOOS=linux go build -mod=readonly

# Now copy it into our base image.
FROM scratch
COPY --from=build /build/src/loghook /loghook
USER 1000
ENV LOGHOOK_GITHUB_WEBHOOK_SECRET "configure_me"
ENTRYPOINT ["/loghook"]
