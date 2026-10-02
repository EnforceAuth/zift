# MCP server image for the published zift release (stdio).
# Linux release assets are amd64 only. aarch64-apple-darwin is macOS, not linux/arm64.
# GitHub publishes a sha256 digest on each release asset; the build checks it.

FROM debian:bookworm-slim AS fetch

ARG ZIFT_VERSION=0.2.3
ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl jq \
    && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) ASSET="zift-x86_64-unknown-linux-gnu.tar.gz" ;; \
      *) echo "No linux release asset for TARGETARCH=${TARGETARCH}. Published linux binaries are amd64 (x86_64-unknown-linux-gnu) only." >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o "/tmp/${ASSET}" \
      "https://github.com/EnforceAuth/zift/releases/download/v${ZIFT_VERSION}/${ASSET}"; \
    DIGEST="$(curl -fsSL \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "https://api.github.com/repos/EnforceAuth/zift/releases/tags/v${ZIFT_VERSION}" \
      | jq -er --arg name "${ASSET}" '.assets[] | select(.name == $name) | .digest')"; \
    case "${DIGEST}" in \
      sha256:*) ;; \
      *) echo "Release v${ZIFT_VERSION} did not publish a sha256 digest for ${ASSET} (got: ${DIGEST})" >&2; exit 1 ;; \
    esac; \
    echo "${DIGEST#sha256:}  /tmp/${ASSET}" | sha256sum -c -; \
    tar -xzf "/tmp/${ASSET}" -C /usr/local/bin zift; \
    chmod 0755 /usr/local/bin/zift

FROM debian:bookworm-slim

RUN groupadd --system --gid 1000 zift \
    && useradd --system --uid 1000 --gid zift --create-home --home-dir /home/zift zift \
    && mkdir -p /workspace \
    && chown zift:zift /workspace

COPY --from=fetch /usr/local/bin/zift /usr/local/bin/zift

USER zift
WORKDIR /workspace
ENTRYPOINT ["zift", "mcp", "--scan-root", "/workspace"]
