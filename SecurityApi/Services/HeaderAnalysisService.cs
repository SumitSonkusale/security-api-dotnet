using SecurityApi.Models;

namespace SecurityApi.Services;

/// <summary>
/// Analyses HTTP security headers and scores them against best practice.
/// </summary>
public sealed class HeaderAnalysisService : IHeaderAnalysisService
{
    private static readonly Dictionary<string, (string severity, string description, string recommendation)> _requiredHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Strict-Transport-Security"] = ("HIGH", "Missing HSTS header — site may be vulnerable to downgrade attacks.", "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
        ["Content-Security-Policy"] = ("HIGH", "Missing CSP header — site is vulnerable to XSS attacks.", "Define a strict Content-Security-Policy"),
        ["X-Content-Type-Options"] = ("MEDIUM", "Missing X-Content-Type-Options — MIME-sniffing may occur.", "Add: X-Content-Type-Options: nosniff"),
        ["X-Frame-Options"] = ("MEDIUM", "Missing X-Frame-Options — site may be vulnerable to clickjacking.", "Add: X-Frame-Options: DENY"),
        ["Referrer-Policy"] = ("LOW", "Missing Referrer-Policy — referrer data may leak.", "Add: Referrer-Policy: no-referrer"),
        ["Permissions-Policy"] = ("LOW", "Missing Permissions-Policy — browser features are unrestricted.", "Add: Permissions-Policy: geolocation=(), microphone=()"),
    };

    private readonly IHttpClientFactory _httpClientFactory;

    public HeaderAnalysisService(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    /// <inheritdoc/>
    public async Task<HeaderAnalysisResponse> AnalyseAsync(string url)
    {
        var client = _httpClientFactory.CreateClient();
        try
        {
            var response = await client.SendAsync(
                new HttpRequestMessage(HttpMethod.Head, url));
            var headers = response.Headers
                .ToDictionary(h => h.Key, h => string.Join(",", h.Value), StringComparer.OrdinalIgnoreCase);
            return AnalyseHeaders(url, headers);
        }
        catch (Exception ex)
        {
            return new HeaderAnalysisResponse(url, false,
                new List<HeaderFinding> { new("Connection", "CRITICAL", $"Could not reach host: {ex.Message}", "Verify the URL is reachable") },
                0, "F");
        }
    }

    /// <inheritdoc/>
    public HeaderAnalysisResponse AnalyseHeaders(string url, Dictionary<string, string> headers)
    {
        var findings = new List<HeaderFinding>();
        int deductions = 0;

        foreach (var (header, (severity, description, recommendation)) in _requiredHeaders)
        {
            if (!headers.ContainsKey(header))
            {
                findings.Add(new HeaderFinding(header, severity, description, recommendation));
                deductions += severity switch { "HIGH" => 20, "MEDIUM" => 10, _ => 5 };
            }
        }

        int score = Math.Max(0, 100 - deductions);
        string grade = score switch
        {
            >= 90 => "A",
            >= 75 => "B",
            >= 60 => "C",
            >= 40 => "D",
            _ => "F"
        };

        bool isHttps = url.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        return new HeaderAnalysisResponse(url, isHttps, findings, score, grade);
    }
}
