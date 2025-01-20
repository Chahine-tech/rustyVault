# TPM SSH Agent

A secure SSH agent implementation with TPM (Trusted Platform Module) integration for Windows, providing enhanced security for SSH key management.

<details>
<summary>Show ASCII Banner</summary>

```txt
<!-- The content below is from docs/banner.txt -->
  _____  ____  __  __   ____  ____  _   _           _                    _   
 |_   _||  _ \|  \/  | / ___||  _ \| | | |         / \    __ _   ___  _| |_ 
   | |  | |_) | |\/| | \___ \| |_) | |_| |  _____ / _ \  / _` | / _ \|_   _|
   | |  |  __/| |  | |  ___) |  __/|  _  | |_____/ ___ \| (_| ||  __/  |_|  
   |_|  |_|   |_|  |_| |____/|_|   |_| |_|     /_/   \_\\__, | \___|       
                                                         |___/               
=============================================================================
                    Secure SSH Agent with TPM Integration
=============================================================================
```
</details>

## Features

- 🔐 **TPM Integration**: Secure key operations using Windows TPM
- 🔑 **Multiple Key Types Support**:
  - RSA (2048/4096 bits)
  - Ed25519
- ⏰ **Key Lifecycle Management**:
  - Automatic key expiration
  - Usage tracking
  - Periodic cleanup of expired keys
- 🛡️ **Security Features**:
  - Secure key storage with AES-256-GCM encryption
  - Hardware-backed cryptographic operations (when TPM is available)
  - Automatic fallback to secure software implementation
- 🔄 **Cross-Platform Development**:
  - Development supported on macOS/Linux
  - Target deployment on Windows
  - Containerized development environment

## Prerequisites

- For development:
  - Docker
  - Nix package manager (optional, but recommended)
  - Rust toolchain (automatically managed by Nix)

- For deployment:
  - Windows 10/11
  - TPM 2.0 (optional, falls back to software implementation if not available)

## Quick Start

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/tpm-ssh-agent.git
   cd tpm-ssh-agent
   ```

2. **Development Environment Setup**:
   
   Using the provided development script:
   ```bash
   # Build the development container
   ./dev.sh build

   # Initialize git hooks
   ./dev.sh init-hooks

   # Start a development shell
   ./dev.sh shell
   ```

   Or using Nix directly:
   ```bash
   # Enable flakes if you haven't already
   mkdir -p ~/.config/nix
   echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf

   # Enter the development environment
   nix develop
   ```

3. **Build and Test**:
   ```bash
   # Check the code
   just check

   # Run tests
   just test

   # Build for Windows
   just build-windows
   ```

## Usage

1. **Start the Agent**:
   ```bash
   ./agent
   ```

2. **Key Management**:
   - Keys are automatically generated on startup
   - Keys can be added with optional expiration:
     ```bash
     # Example: Add a key that expires in 24 hours
     ssh-add -t 86400 /path/to/key
     ```

3. **View Current Keys**:
   ```bash
   ssh-add -l
   ```

4. **Remove All Keys**:
   ```bash
   ssh-add -D
   ```

## Development

The project uses a Nix-based development environment that ensures consistent tooling across platforms. Key development commands:

```bash
# Format code
just fmt

# Run linter
just lint

# Run security audit
just audit

# Check Windows build
just check-windows
```

## Architecture

The agent consists of several key components:

- **TPM Provider**: Interfaces with the Windows TPM for cryptographic operations
- **Key Store**: Manages secure storage of SSH keys
- **SSH Agent Server**: Implements the SSH agent protocol
- **Mock Provider**: Provides a software fallback when TPM is unavailable

## Security Considerations

- All keys are encrypted at rest using AES-256-GCM
- TPM operations are used when available for enhanced security
- The mock provider uses ring's secure implementations
- Regular security audits are enforced through CI/CD

## Contributing

1. Fork the repository
2. Create your feature branch
3. Run tests and linting
4. Submit a pull request

## License

[Add your chosen license here]

## Acknowledgments

- Windows TPM integration based on the Windows CryptoAPI
- Cryptographic operations powered by ring
- Development environment managed by Nix 