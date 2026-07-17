using System.Security.Cryptography;
using System.Text.RegularExpressions;
using SecurityApi.Models;

namespace SecurityApi.Services;

/// <summary>
/// Looks up file hashes against a local sample set.
/// In production this would integrate with VirusTotal, MalwareBazaar, etc.
/// </summary>
public sealed class HashLookupService : IHashLookupService
{
    private static readonly Dictionary<string, (string name, string family)> _knownHashes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["44d88612fea8a8f36de82e1278abb02f"] = ("EICAR-Test", "TestFile"),
        ["3395856ce81f2b7382dee72602f798b642f14d4"] = ("EICAR-Test-SHA1", "TestFile"),
        ["275a021bbfb6489e54d471899f7db9d1663fc695bf4197b9e5a6d7e9b4d4a9c5"] = ("EICAR-SHA256", "TestFile"),
    };

    private static readonly Regex _md5Regex = new(@"^[a-fA-F0-9]{32}$", RegexOptions.Compiled);
    private static readonly Regex _sha1Regex = new(@"^[a-fA-F0-9]{40}$", RegexOptions.Compiled);
    private static readonly Regex _sha256Regex = new(@"^[a-fA-F0-9]{64}$", RegexOptions.Compiled);

    /// <inheritdoc/>
    public Task<HashLookupResponse> LookupAsync(string hash, string hashType)
    {
        if (!IsValidHash(hash, hashType))
        {
            return Task.FromResult(new HashLookupResponse(
                hash, hashType, false, null, null, 0, "local"));
        }

        bool found = _knownHashes.TryGetValue(hash, out var info);

        return Task.FromResult(new HashLookupResponse(
            hash,
            hashType,
            found,
            found ? info.name : null,
            found ? info.family : null,
            found ? 1 : 0,
            "local-sample-db"
        ));
    }

    /// <summary>Validate that a hash matches the expected format for its type.</summary>
    public static bool IsValidHash(string hash, string hashType) =>
        hashType.ToUpperInvariant() switch
        {
            "MD5" => _md5Regex.IsMatch(hash),
            "SHA1" => _sha1Regex.IsMatch(hash),
            "SHA256" => _sha256Regex.IsMatch(hash),
            _ => false
        };
}
