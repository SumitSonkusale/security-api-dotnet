using Microsoft.AspNetCore.Mvc;
using SecurityApi.Models;
using SecurityApi.Services;

namespace SecurityApi.Controllers;

/// <summary>
/// Threat intelligence API — header analysis, IP reputation, and hash lookup.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public sealed class SecurityController : ControllerBase
{
    private readonly IHeaderAnalysisService _headerService;
    private readonly IIpReputationService _ipService;
    private readonly IHashLookupService _hashService;
    private readonly ILogger<SecurityController> _logger;

    public SecurityController(
        IHeaderAnalysisService headerService,
        IIpReputationService ipService,
        IHashLookupService hashService,
        ILogger<SecurityController> logger)
    {
        _headerService = headerService;
        _ipService = ipService;
        _hashService = hashService;
        _logger = logger;
    }

    /// <summary>Analyse the HTTP security headers of a URL.</summary>
    /// <param name="url">The URL to analyse (must be http/https).</param>
    [HttpGet("headers")]
    [ProducesResponseType(typeof(HeaderAnalysisResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> AnalyseHeaders([FromQuery] string url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return BadRequest(new { error = "url parameter is required" });

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            return BadRequest(new { error = "url must be a valid http or https URL" });

        _logger.LogInformation("Analysing headers for {Url}", url);
        var result = await _headerService.AnalyseAsync(url);
        return Ok(result);
    }

    /// <summary>Analyse a pre-supplied set of HTTP headers.</summary>
    [HttpPost("headers")]
    [ProducesResponseType(typeof(HeaderAnalysisResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public IActionResult AnalyseHeadersFromBody([FromBody] HeaderAnalysisRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Url))
            return BadRequest(new { error = "url is required" });

        var headers = request.Headers ?? new Dictionary<string, string>();
        var result = _headerService.AnalyseHeaders(request.Url, headers);
        return Ok(result);
    }

    /// <summary>Check the reputation of an IP address.</summary>
    /// <param name="ip">IPv4 or IPv6 address to check.</param>
    [HttpGet("ip/{ip}")]
    [ProducesResponseType(typeof(IpReputationResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> CheckIpReputation(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
            return BadRequest(new { error = "ip parameter is required" });

        _logger.LogInformation("Checking IP reputation for {Ip}", ip);
        var result = await _ipService.CheckAsync(ip);
        return Ok(result);
    }

    /// <summary>Look up a file hash against known malware databases.</summary>
    /// <param name="hash">MD5, SHA1, or SHA256 hash string.</param>
    [HttpGet("hash/{hash}")]
    [ProducesResponseType(typeof(HashLookupResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> LookupHash(string hash)
    {
        if (string.IsNullOrWhiteSpace(hash))
            return BadRequest(new { error = "hash parameter is required" });

        string hashType = IHashLookupService.DetectHashType(hash);
        if (hashType == "UNKNOWN")
            return BadRequest(new { error = "hash must be a valid MD5 (32), SHA1 (40), or SHA256 (64) hex string" });

        _logger.LogInformation("Looking up hash {Hash} (type: {HashType})", hash, hashType);
        var result = await _hashService.LookupAsync(hash, hashType);
        return Ok(result);
    }

    /// <summary>Health check endpoint.</summary>
    [HttpGet("health")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult Health() =>
        Ok(new { status = "healthy", timestamp = DateTime.UtcNow, version = "1.0.0" });
}
