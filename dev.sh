#!/bin/bash

# Build the development container
build() {
    docker build -t rust-tpm-dev:latest -f Dockerfile.dev . --no-cache
}

# Run an interactive shell in the container
shell() {
    docker run --rm -it \
        -v "$(pwd)":/app \
        -v "${HOME}/.cargo/registry":/root/.cargo/registry \
        rust-tpm-dev:latest \
        nix develop
}

# Run a specific command in the container
run() {
    docker run --rm \
        -v "$(pwd)":/app \
        -v "${HOME}/.cargo/registry":/root/.cargo/registry \
        rust-tpm-dev:latest \
        nix develop --command "$@"
}

# Show usage if no arguments provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 {build|shell|run <command>}"
    exit 1
fi

# Handle commands
case "$1" in
    "build")
        build
        ;;
    "shell")
        shell
        ;;
    "run")
        shift
        run "$@"
        ;;
    *)
        echo "Unknown command: $1"
        echo "Usage: $0 {build|shell|run <command>}"
        exit 1
        ;;
esac