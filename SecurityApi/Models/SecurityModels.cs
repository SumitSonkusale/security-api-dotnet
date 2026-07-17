namespace SecurityApi.Models;

/// <summary>Request model for header analysis.</summary>
public record HeaderAnalysisRequest(
    string Url,
    Dictionary<string, string>? Headers = null
);

/// <summary>A single header finding with severity and recommendation.</summary>
public record HeaderFinding(
    string Header,
    string Severity,
    string Description,
    string Recommendation
);

/// <summary>Response model for header analysis.</summary>
public record HeaderAnalysisResponse(
    string Url,
    bool IsHttps,
    List<HeaderFinding> Findings,
    int Score,
    string Grade
);

/// <summary>Request model for IP reputation check.</summary>
public record IpReputationRequest(string IpAddress);

/// <summary>Response model for IP reputation check.</summary>
public record IpReputationResponse(
    string IpAddress,
    bool IsMalicious,
    string RiskLevel,
    List<string> Tags,
    string Country,
    string Isp,
    string Source
);

/// <summary>Request model for file hash lookup.</summary>
public record HashLookupRequest(
    string Hash,
    string HashType
);

/// <summary>Response model for file hash lookup.</summary>
public record HashLookupResponse(
    string Hash,
    string HashType,
    bool IsMalicious,
    string? MalwareName,
    string? MalwareFamily,
    int DetectionCount,
    string Source
);
