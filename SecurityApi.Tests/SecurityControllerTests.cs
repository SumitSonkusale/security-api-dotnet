using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using SecurityApi.Controllers;
using SecurityApi.Models;
using SecurityApi.Services;
using Xunit;

namespace SecurityApi.Tests;

/// <summary>
/// Unit tests for SecurityController endpoints.
/// Tests cover happy paths and validation failure branches.
/// </summary>
public class SecurityControllerTests
{
    private readonly Mock<IHeaderAnalysisService> _headerSvc = new();
    private readonly Mock<IIpReputationService> _ipSvc = new();
    private readonly Mock<IHashLookupService> _hashSvc = new();
    private readonly Mock<ILogger<SecurityController>> _logger = new();
    private readonly SecurityController _controller;

    public SecurityControllerTests()
    {
        _controller = new SecurityController(
            _headerSvc.Object,
            _ipSvc.Object,
            _hashSvc.Object,
            _logger.Object);
    }

    // ---- Header Analysis (body) ----

    [Fact]
    public void AnalyseHeadersFromBody_EmptyUrl_ReturnsBadRequest()
    {
        // Controller checks request.Url for null/whitespace
        var request = new HeaderAnalysisRequest(Url: "", Headers: null);
        var result = _controller.AnalyseHeadersFromBody(request);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public void AnalyseHeadersFromBody_ValidRequest_ReturnsOk()
    {
        var findings = new List<HeaderFinding>();
        var response = new HeaderAnalysisResponse(
            Url: "https://example.com",
            IsHttps: true,
            Findings: findings,
            Score: 85,
            Grade: "B"
        );
        _headerSvc
            .Setup(s => s.AnalyseHeaders(
                It.IsAny<string>(),
                It.IsAny<Dictionary<string, string>>()))
            .Returns(response);

        var request = new HeaderAnalysisRequest(
            Url: "https://example.com",
            Headers: new Dictionary<string, string> { ["X-Content-Type-Options"] = "nosniff" }
        );
        var result = _controller.AnalyseHeadersFromBody(request);
        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.Equal(response, ok.Value);
    }

    // ---- IP Reputation ----

    [Fact]
    public async Task CheckIpReputation_EmptyIp_ReturnsBadRequest()
    {
        var result = await _controller.CheckIpReputation("");
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task CheckIpReputation_ValidIp_ReturnsOk()
    {
        var response = new IpReputationResponse(
            IpAddress: "8.8.8.8",
            IsMalicious: false,
            RiskLevel: "Low",
            Tags: new List<string>(),
            Country: "US",
            Isp: "Google LLC",
            Source: "local"
        );
        _ipSvc
            .Setup(s => s.CheckAsync("8.8.8.8"))
            .ReturnsAsync(response);

        var result = await _controller.CheckIpReputation("8.8.8.8");
        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.Equal(response, ok.Value);
    }

    // ---- Hash Lookup ----

    [Fact]
    public async Task LookupHash_EmptyHash_ReturnsBadRequest()
    {
        var result = await _controller.LookupHash("");
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task LookupHash_InvalidHashFormat_ReturnsBadRequest()
    {
        // "not-a-hash" has length != 32/40/64 so DetectHashType returns "UNKNOWN"
        var result = await _controller.LookupHash("not-a-hash");
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task LookupHash_ValidMd5_ReturnsOk()
    {
        // 32 hex chars -> detected as MD5
        var md5 = new string('a', 32);
        var response = new HashLookupResponse(
            Hash: md5,
            HashType: "MD5",
            IsMalicious: false,
            MalwareName: null,
            MalwareFamily: null,
            DetectionCount: 0,
            Source: "local"
        );
        _hashSvc
            .Setup(s => s.LookupAsync(md5, "MD5"))
            .ReturnsAsync(response);

        var result = await _controller.LookupHash(md5);
        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.Equal(response, ok.Value);
    }

    // ---- Health ----

    [Fact]
    public void Health_ReturnsOkWithStatus()
    {
        var result = _controller.Health();
        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.NotNull(ok.Value);
    }
}
