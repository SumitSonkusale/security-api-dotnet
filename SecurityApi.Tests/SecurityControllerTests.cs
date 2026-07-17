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

    // ---- Header Analysis ----

    [Fact]
    public async Task AnalyzeHeaders_MissingBody_ReturnsBadRequest()
    {
        var result = await _controller.AnalyzeHeaders(null!);
        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.NotNull(bad.Value);
    }

    [Fact]
    public async Task AnalyzeHeaders_ValidRequest_ReturnsOk()
    {
        var response = new HeaderAnalysisResponse
        {
            Score = 85,
            Grade = "B",
            Missing = new List<string>(),
            Present = new List<string> { "X-Content-Type-Options" },
            Recommendations = new List<string>()
        };
        _headerSvc
            .Setup(s => s.AnalyzeAsync(It.IsAny<Dictionary<string, string>>()))
            .ReturnsAsync(response);

        var request = new HeaderAnalysisRequest
        {
            Headers = new Dictionary<string, string> { ["X-Content-Type-Options"] = "nosniff" }
        };
        var result = await _controller.AnalyzeHeaders(request);
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
        var response = new IpReputationResponse
        {
            Ip = "8.8.8.8",
            RiskScore = 5,
            IsKnownMalicious = false,
            Country = "US",
            Tags = new List<string>()
        };
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
        var result = await _controller.LookupHash("not-a-hash");
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task LookupHash_ValidMd5_ReturnsOk()
    {
        var md5 = new string('a', 32); // valid MD5 length
        var response = new HashLookupResponse
        {
            Hash = md5,
            HashType = "MD5",
            IsMalicious = false,
            DetectionCount = 0,
            Source = "local"
        };
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
