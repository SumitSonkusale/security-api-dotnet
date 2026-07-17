using System.Net;
using SecurityApi.Models;

namespace SecurityApi.Services;

/// <summary>
/// Checks IP reputation using basic heuristics and private-range detection.
/// In a production system this would integrate with AbuseIPDB, VirusTotal, etc.
/// </summary>
public sealed class IpReputationService : IIpReputationService
{
    private static readonly HashSet<string> _knownMaliciousSamples = new()
    {
        "198.51.100.1", "203.0.113.0", "192.0.2.1"
    };

    /// <inheritdoc/>
    public Task<IpReputationResponse> CheckAsync(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var parsed))
        {
            return Task.FromResult(new IpReputationResponse(
                ipAddress, false, "UNKNOWN", new List<string> { "invalid-ip" },
                "N/A", "N/A", "local-validation"));
        }

        bool isPrivate = IsPrivateRange(parsed);
        bool isMalicious = _knownMaliciousSamples.Contains(ipAddress);

        var tags = new List<string>();
        if (isPrivate) tags.Add("private-range");
        if (isMalicious) tags.Add("known-malicious");

        string riskLevel = (isMalicious, isPrivate) switch
        {
            (true, _) => "HIGH",
            (false, true) => "INFO",
            _ => "LOW"
        };

        return Task.FromResult(new IpReputationResponse(
            ipAddress,
            isMalicious,
            riskLevel,
            tags,
            "N/A",
            "N/A",
            "local-heuristic"
        ));
    }

    private static bool IsPrivateRange(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        return bytes[0] switch
        {
            10 => true,
            172 => bytes[1] >= 16 && bytes[1] <= 31,
            192 => bytes[1] == 168,
            127 => true,
            _ => false
        };
    }
}
