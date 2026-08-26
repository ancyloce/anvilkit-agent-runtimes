# Image for the page-change-manager Agent Runtime Unit.
#
# One image per Agent, built from the shared source tree. Units share the
# runtime host and share nothing in production: this image is released,
# scaled, and rolled back on its own.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod ./
COPY contracts ./contracts
COPY runtime ./runtime
COPY agents/page-change-manager ./agents/page-change-manager
# Static build: the runtime carries no shell and no package manager, so a
# compromised turn has nothing to execute.
RUN CGO_ENABLED=0 go build -trimpath -o /out/page-change-manager ./agents/page-change-manager

FROM gcr.io/distroless/static-debian12:nonroot
# Non-root and read-only by construction. A runtime unit never writes durable
# state; anything it needed to persist would belong to the control plane.
USER nonroot:nonroot
COPY --from=build /out/page-change-manager /page-change-manager
ENTRYPOINT ["/page-change-manager"]
