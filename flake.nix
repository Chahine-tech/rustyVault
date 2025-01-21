{
  description = "SSH Agent with TPM support (Cross-platform development environment)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            # Rust toolchain with cross-compilation support
            (rust-bin.stable.latest.default.override {
              # Include both native target and Windows
              targets = [ 
                (if system == "x86_64-darwin" then "x86_64-apple-darwin"
                 else if system == "aarch64-darwin" then "aarch64-apple-darwin"
                 else "x86_64-unknown-linux-gnu")
                "x86_64-pc-windows-msvc"
              ];
              extensions = [ 
                "rust-src"
                "llvm-tools-preview"
                "rustfmt"
                "clippy"
              ];
            })
            rust-analyzer
            
            # Additional development tools
            cargo-edit     # For easy dependency management
            cargo-watch   # For development with auto-reload
            cargo-audit   # For security audits
            cargo-expand  # To see expanded macro code
            
            # Git tools
            git
            gh           # GitHub CLI
            
            # General development tools
            just         # Command runner
            nixpkgs-fmt  # Formatter for Nix files
          ];

          shellHook = ''
            echo "Configuring cross-platform development environment"
            echo "Native target: ${system}"
            echo "Cross target: x86_64-pc-windows-msvc"
            
            # Configure cargo for cross-compilation
            mkdir -p .cargo
            cat > .cargo/config.toml << EOF
            [alias]
            check-all = "check --all-targets --all-features"
            test-all = "test --all-targets --all-features"
            build-windows = "build --target x86_64-pc-windows-msvc"

            [target.x86_64-pc-windows-msvc]
            rustflags = [
                "-C", "target-feature=+crt-static",
                "-D", "warnings"
            ]
            EOF

            # Create justfile if it doesn't exist
            if [ ! -f justfile ]; then
              cat > justfile << EOF
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
            EOF
            fi
          '';

          # Environment variables for development
          RUST_BACKTRACE = "1";
          RUST_LOG = "debug";
        };
      });
}