FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2
COPY --chmod=0555 audit-collector /usr/local/bin/audit-collector
USER 65532:65532
ENV AUDIT_CONFIG=/config/collector.json
ENTRYPOINT ["/usr/local/bin/audit-collector"]
