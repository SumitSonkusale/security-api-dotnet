# LinkedIn Post — Project 3: C#/.NET Core Security API

---

Built a RESTful security API with ASP.NET Core 8 — the third project in my backend security portfolio.

The API exposes three core endpoints:

- **Header analysis** — POST a dictionary of HTTP response headers and receive a scored security grade with specific recommendations (HSTS, CSP, X-Frame-Options, etc.)
- **IP reputation check** — GET endpoint that returns a risk score, known-malicious flag, country, and threat tags for a given IP address
- **Hash lookup** — GET endpoint that detects whether a supplied MD5, SHA1, or SHA256 hash matches known-malicious file signatures

Architectural decisions I focused on:

- Dependency injection throughout — controller depends on interfaces, not concrete classes, making every layer independently testable
- Clean separation between models, service interfaces, service implementations, and controller logic
- xUnit + Moq unit tests covering happy paths and error cases for all four endpoints
- GitHub Actions CI pipeline: restore, build (Release), and test on every push to main

Tech stack: ASP.NET Core 8, C# 12, xUnit, Moq, GitHub Actions

Code: https://github.com/SumitSonkusale/security-api-dotnet

#dotnet #csharp #aspnetcore #cybersecurity #softwaredevelopment #github #ci #unittesting #restapi
