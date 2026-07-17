# security-api-dotnet

![CI](https://github.com/SumitSonkusale/security-api-dotnet/actions/workflows/ci.yml/badge.svg)

A RESTful security API built with **ASP.NET Core 8** that exposes endpoints for HTTP security header analysis, IP reputation checks, and file hash lookups. Designed as a demonstration of clean architecture, dependency injection, and testable service layers in C#.

---

## Features

| Endpoint | Method | Description |
|---|---|---|
| `/security/headers` | POST | Analyse HTTP response headers and return a security grade |
| `/security/ip/{ip}` | GET | Check IP reputation and risk score |
| `/security/hash/{hash}` | GET | Look up MD5/SHA1/SHA256 hash against a known-malicious database |
| `/security/health` | GET | Health-check endpoint |

---

## Project Structure

```
security-api-dotnet/
├── SecurityApi/
│   ├── Controllers/
│   │   └── SecurityController.cs   # Route handlers
│   ├── Models/
│   │   └── SecurityModels.cs       # Request/response records
│   ├── Services/
│   │   ├── ISecurityServices.cs    # Service interfaces
│   │   ├── HeaderAnalysisService.cs
│   │   ├── IpReputationService.cs
│   │   └── HashLookupService.cs
│   ├── Program.cs
│   └── SecurityApi.csproj
├── SecurityApi.Tests/
│   ├── SecurityControllerTests.cs  # xUnit unit tests (Moq)
│   └── SecurityApi.Tests.csproj
├── .github/workflows/ci.yml        # GitHub Actions CI
└── SecurityApi.sln
```

---

## Tech Stack

- **ASP.NET Core 8** — web framework
- **C# 12** — language
- **xUnit** — unit testing
- **Moq** — mocking framework
- **GitHub Actions** — CI (build + test on every push)

---

## Getting Started

### Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

### Build

```bash
git clone https://github.com/SumitSonkusale/security-api-dotnet.git
cd security-api-dotnet
dotnet restore
dotnet build
```

### Run

```bash
cd SecurityApi
dotnet run
```

The API will be available at `https://localhost:5001`. Swagger UI is available at `/swagger`.

### Test

```bash
dotnet test --verbosity normal
```

---

## API Examples

### Analyse HTTP headers

```http
POST /security/headers
Content-Type: application/json

{
  "headers": {
    "Strict-Transport-Security": "max-age=31536000",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY"
  }
}
```

### Check IP reputation

```http
GET /security/ip/8.8.8.8
```

### Look up a file hash

```http
GET /security/hash/d41d8cd98f00b204e9800998ecf8427e
```

---

## CI/CD

GitHub Actions runs on every push and pull request to `main`:

1. Checkout code
2. Set up .NET 8
3. `dotnet restore`
4. `dotnet build --configuration Release`
5. `dotnet test --configuration Release`

---

## License

MIT — see [LICENSE](LICENSE).
