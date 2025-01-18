{
  description = "SSH Agent with TPM support (Windows-targeted development environment)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    pre-commit-hooks = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, pre-commit-hooks, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # Configuration des pre-commit hooks
        pre-commit = pre-commit-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            rustfmt.enable = true;
            clippy.enable = true;
            cargo-check.enable = true;
            cargo-test.enable = true;
          };
        };

      in
      {
        checks = {
          pre-commit-check = pre-commit;
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            # Rust toolchain avec la cible Windows
            (rust-bin.stable.latest.default.override {
              targets = [ "x86_64-pc-windows-msvc" ];
              extensions = [ 
                "rust-src"
                "llvm-tools-preview"
                "rustfmt"
                "clippy"
              ];
            })
            rust-analyzer
            
            # Outils de développement additionnels
            cargo-edit     # Pour gérer les dépendances facilement
            cargo-watch   # Pour le développement avec auto-reload
            cargo-audit   # Pour les audits de sécurité
            cargo-expand  # Pour voir le code macro expansé
            
            # Outils Git
            git
            gh           # GitHub CLI
            
            # Outils de développement généraux
            just         # Command runner
            nixpkgs-fmt  # Formateur pour les fichiers Nix
          ];

          inherit (pre-commit) shellHook;

          # Variables d'environnement pour le développement
          RUST_BACKTRACE = "1";
          RUST_LOG = "debug";
          
          # Configuration supplémentaire
          shellHook = ''
            echo "Configuring Windows-targeted development environment"
            echo "Note: This environment is for development only. The project must be built and run on Windows."
            
            # Configuration de cargo pour cibler Windows par défaut
            mkdir -p .cargo
            cat > .cargo/config.toml << EOF
            [build]
            target = "x86_64-pc-windows-msvc"

            [target.x86_64-pc-windows-msvc]
            rustflags = [
                "-C", "target-feature=+crt-static",
                "-D", "warnings"
            ]

            [alias]
            check-all = "check --all-targets --all-features"
            test-all = "test --all-targets --all-features"
            EOF

            # Création d'un fichier justfile si non existant
            if [ ! -f justfile ]; then
              cat > justfile << EOF
            # Liste toutes les commandes disponibles
            default:
                @just --list

            # Vérifie le code
            check:
                cargo check-all

            # Lance les tests
            test:
                cargo test-all

            # Formate le code
            fmt:
                cargo fmt
                nixpkgs-fmt .

            # Vérifie le style
            lint:
                cargo clippy -- -D warnings

            # Audit des dépendances
            audit:
                cargo audit
            EOF
            fi
          '';
        };
      });
} 