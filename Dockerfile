# ─── Étage build : compile le binaire Rust en mode release ─────────────────────
FROM rust:1-bookworm AS builder
WORKDIR /app

# Copie des manifestes d'abord (meilleur cache de couches Docker tant que les
# dépendances ne changent pas).
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# CACHEBUST : changer cette valeur force la recompilation à partir d'ici (utile
# quand Dokploy sert une image périmée malgré un git pull).
ARG CACHEBUST=2026-06-18-01
RUN echo "CACHEBUST=${CACHEBUST}" && cargo build --release

# ─── Étage runtime : image minimale, sans toolchain ────────────────────────────
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 appuser

COPY --from=builder /app/target/release/pseudo-gateway /usr/local/bin/pseudo-gateway

USER appuser
EXPOSE 8080
ENV RUST_LOG=info
# La passerelle lit sa config dans l'environnement : MASTER_KEY / PSEUDO_KEY_*,
# VAULT_STORE, REDIS_URL, GATEWAY_API_KEY, PRESIDIO_URL… (voir .env.example).
ENTRYPOINT ["/usr/local/bin/pseudo-gateway"]
