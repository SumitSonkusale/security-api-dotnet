using SecurityApi.Models;

namespace SecurityApi.Services;

/// <summary>
/// Analyses HTTP security headers for a given URL.
/// </summary>
public interface IHeaderAnalysisService
{
    /// <summary>Analyse the security headers of a URL.</summary>
    Task<HeaderAnalysisResponse> AnalyseAsync(string url);

    /// <summary>Analyse a pre-supplied header dictionary directly.</summary>
    HeaderAnalysisResponse AnalyseHeaders(string url, Dictionary<string, string> headers);
}

/// <summary>
/// Checks the reputation of an IP address.
/// </summary>
public interface IIpReputationService
{
    /// <summary>Check reputation of an IP address.</summary>
    Task<IpReputationResponse> CheckAsync(string ipAddress);
}

/// <summary>
/// Looks up a file hash against known malware databases.
/// </summary>
public interface IHashLookupService
{
    /// <summary>Look up a file hash (MD5, SHA1, or SHA256).</summary>
    Task<HashLookupResponse> LookupAsync(string hash, string hashType);

    /// <summary>Determine the hash type from its length.</summary>
    static string DetectHashType(string hash) => hash.Length switch
    {
        32 => "MD5",
        40 => "SHA1",
        64 => "SHA256",
        _ => "UNKNOWN"
    };
}
