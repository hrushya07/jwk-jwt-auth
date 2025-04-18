# JWT Auth Service (with JWKS)

This is a Go-based authentication service that implements JWT token validation using JWKS (JSON Web Key Set). It utilizes the [`lestrrat-go/jwx`](https://github.com/lestrrat-go/jwx/v3) package for working with JWTs and JWKS, and [`cobra`](https://github.com/spf13/cobra) for building a CLI interface.

## Features

- JWT validation using JWKS
- CLI interface built with Cobra
- Lightweight and easy to extend

## Tech Stack

- **Go**
- **JWT / JWKS** via [`lestrrat-go/jwx`](https://github.com/lestrrat-go/jwx/v3)
- **CLI** via [Cobra](https://github.com/spf13/cobra)

## Getting Started

### Prerequisites

- Go 1.23 or later installed

### Installation

Clone the repo and install the dependencies:

```bash
git clone https://github.com/hrushya07/jwk-jwt-auth.git
cd jwk-jwt-auth
go mod tidy
```

### Running the Services
```bash
go run main.go menu
```

### Made with 💻, ☕, and a lot of JWTs.