# Image for the page-candidate-specialist Agent Runtime Unit.
#
# One image per Agent, built from the shared source tree. Units share the
# runtime host and share nothing in production: this image is released,
# scaled, and rolled back on its own.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod ./
COPY contracts ./contracts
COPY runtime ./runtime
COPY agents/page-candidate-specialist ./agents/page-candidate-specialist
# Static build: the runtime carries no shell and no package manager, so a
# compromised turn has nothing to execute.
RUN CGO_ENABLED=0 go build -trimpath -o /out/page-candidate-specialist ./agents/page-candidate-specialist

FROM gcr.io/distroless/static-debian12:nonroot
# Non-root and read-only by construction. A runtime unit never writes durable
# state; anything it needed to persist would belong to the control plane.
USER nonroot:nonroot
COPY --from=build /out/page-candidate-specialist /page-candidate-specialist
ENTRYPOINT ["/page-candidate-specialist"]
