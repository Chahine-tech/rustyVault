#!/bin/bash

# Build the development container
build() {
    docker build -t rust-tpm-dev -f Dockerfile.dev .
}

# Run an interactive shell in the container
shell() {
    docker run -it --rm \
        -v "$(pwd):/app" \
        -v "cargo-cache:/root/.cargo" \
        -v "git-config:/root/.config/git" \
        rust-tpm-dev
}

# Run a specific command in the container
run() {
    docker run -it --rm \
        -v "$(pwd):/app" \
        -v "cargo-cache:/root/.cargo" \
        -v "git-config:/root/.config/git" \
        rust-tpm-dev \
        nix develop --command "$@"
}

# Initialize git hooks
init_hooks() {
    docker run -it --rm \
        -v "$(pwd):/app" \
        -v "cargo-cache:/root/.cargo" \
        -v "git-config:/root/.config/git" \
        rust-tpm-dev \
        nix develop --command git init
}

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
    "init-hooks")
        init_hooks
        ;;
    *)
        echo "Usage: $0 {build|shell|run <command>|init-hooks}"
        echo ""
        echo "Commands:"
        echo "  build         Build the development container"
        echo "  shell         Start an interactive shell in the container"
        echo "  run <cmd>     Run a specific command in the container"
        echo "  init-hooks    Initialize git hooks in the project"
        echo ""
        echo "Examples:"
        echo "  $0 build              # Build the container"
        echo "  $0 shell              # Start a shell"
        echo "  $0 run just test      # Run tests"
        echo "  $0 run just check     # Check code"
        echo "  $0 init-hooks         # Setup git hooks"
        exit 1
        ;;
esac 