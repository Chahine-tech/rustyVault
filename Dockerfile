# Build stage
FROM nixos/nix:latest AS builder

# Enable flakes
RUN echo "experimental-features = nix-command flakes" >> /etc/nix/nix.conf

# Create development directory
WORKDIR /app

# Copy Nix files
COPY flake.nix flake.lock ./

# Build the development environment and cleanup
RUN nix develop --build && \
    nix-collect-garbage -d

# Final stage
FROM nixos/nix:latest

# Enable flakes
RUN echo "experimental-features = nix-command flakes" >> /etc/nix/nix.conf

# Create development directory
WORKDIR /app

# Copy only necessary Nix store paths
COPY --from=builder /nix/store /nix/store
COPY --from=builder /nix/var /nix/var

# Copy project files
COPY . .

# Set default command to enter development shell
CMD ["nix", "develop"]