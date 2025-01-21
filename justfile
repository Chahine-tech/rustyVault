# List all available commands
default:
    @just --list

# Check the code (native target)
check:
    cargo check-all

# Check the code (Windows target)
check-windows:
    cargo check --target x86_64-pc-windows-msvc

# Run tests (native target)
test:
    cargo test-all

# Build for Windows
build-windows:
    cargo build-windows

# Format code
fmt:
    cargo fmt
    nixpkgs-fmt .

# Check style
lint:
    cargo clippy -- -D warnings
    cargo clippy --target x86_64-pc-windows-msvc -- -D warnings

# Audit dependencies
audit:
    cargo audit
