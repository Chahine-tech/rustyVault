FROM rust:latest

# Install cross-compilation tools
RUN apt-get update && apt-get install -y \
    gcc-mingw-w64 \
    mingw-w64 \
    wine \
    clang \
    libclang-dev \
    pkg-config \
    libssl-dev

# Install Windows target
RUN rustup target add x86_64-pc-windows-gnu

WORKDIR /app

# Copy project files
COPY Cargo.toml Cargo.lock* ./
COPY src ./src

# Pre-cache dependencies
RUN cargo fetch

# Build for Windows
RUN cargo build --target x86_64-pc-windows-gnu --verbose

# Optional: Use wine to test the executable
CMD ["wine", "./target/x86_64-pc-windows-gnu/debug/agent.exe"]
