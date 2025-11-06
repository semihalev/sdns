# ML-Based DNS Attack Defense Middleware

An intelligent middleware for SDNS that uses machine learning techniques to detect and prevent DNS amplification and reflection attacks in real-time.

## Overview

This middleware implements a hybrid approach combining rule-based detection with statistical anomaly detection to identify and block DNS-based attacks:

- **DNS Amplification Attacks**: Detects queries designed to generate large responses
- **DNS Reflection Attacks**: Identifies spoofed source IPs attempting to reflect traffic
- **DNS Scanning**: Recognizes scanning behavior patterns
- **Rate-based Attacks**: Tracks query rates per IP address

## Features

### Intelligent Detection

- **Feature Extraction**: Analyzes query type, amplification potential, EDNS buffer size, and protocol
- **Per-IP Profiling**: Maintains behavioral profiles using Exponential Moving Averages (EMA)
- **Multi-Factor Scoring**: Combines query-level and profile-level anomaly scores
- **Online Learning**: Adapts to normal traffic patterns over time

### Attack Detection Capabilities

1. **High-Risk Query Types**: ANY, DNSKEY, RRSIG, TXT, MX, SOA
2. **Amplification Factor Analysis**: Based on US-CERT research (TA13-088A)
3. **Behavioral Analysis**: Query rate, diversity, and patterns
4. **Protocol-Aware**: Different risk scores for UDP vs TCP

### Operational Modes

- **Block Mode**: Actively blocks suspicious queries (returns REFUSED)
- **Learning Mode**: Collects data without blocking (for threshold tuning)
- **Log-Only Mode**: Logs suspicious queries without blocking

## Configuration

Add the following to your `sdns.conf` or `sdns.toml`:

```toml
# Enable ML-based DNS attack defense
mldefenseenabled = true

# Enable blocking mode (if false, only logs suspicious queries)
mldefenseblockmode = true

# Enable learning mode (collect data but don't block)
# Useful for initial deployment and threshold tuning
mldefenselearningmode = false

# Query anomaly score threshold (0-100)
# Blocks queries with anomaly score above this value
mldefensequerythreshold = 60.0

# IP profile risk score threshold (0-100)
# Blocks IPs with behavioral risk score above this value
mldefenseprofilethreshold = 70.0

# Combined score threshold (0-100)
# Blocks when weighted combination exceeds this value
mldefensecombinedthreshold = 80.0

# Log suspicious queries that don't meet blocking threshold
mldefenselogsuspicious = false
```

## How It Works

### 1. Feature Extraction

For each DNS query, the middleware extracts:

- Query type and amplification potential
- Request size and EDNS buffer size
- Protocol (UDP, TCP, DoH, DoQ)
- DNSSEC flags

### 2. Anomaly Scoring

**Query-Level Score** (0-100):
- High amplification potential: +40 points
- High-risk query type: +25 points
- Large EDNS buffer: +15 points
- UDP protocol: +10 points

**Profile-Level Score** (0-100):
- High query rate: +40 points
- High average anomaly: +30 points
- High amplification factor: +20 points
- Query type diversity (scanning): +15 points

**Combined Score**:
```
Combined = 0.4 × QueryScore + 0.6 × ProfileScore
```

### 3. Decision Making

A query is blocked if:
- Query score ≥ query threshold, OR
- Profile score ≥ profile threshold, OR
- Combined score ≥ combined threshold

## Amplification Factors

Based on [US-CERT Alert TA13-088A](https://www.us-cert.gov/ncas/alerts/TA13-088A):

| Query Type | Amplification Factor |
|------------|---------------------|
| ANY        | 179x                |
| DNSKEY     | 120x                |
| RRSIG      | 90x                 |
| TXT        | 73x                 |
| MX         | 51x                 |
| SOA        | 47x                 |
| NS         | 37x                 |
| SRV        | 30x                 |
| AAAA       | 23x                 |
| PTR        | 10x                 |
| A          | 8x                  |

## Prometheus Metrics

The middleware exposes the following metrics at `/metrics`:

```
# Total queries analyzed
mldefense_queries_total

# Blocked queries by reason
mldefense_blocked_total{reason}

# Suspicious but not blocked queries
mldefense_suspicious_total

# Distribution of anomaly scores
mldefense_score_distribution

# Distribution of amplification factors
mldefense_amplification_factor

# Active IP profiles being tracked
mldefense_ip_profiles_active

# Queries by type and risk level
mldefense_query_type_total{qtype,risk_level}

# Current block rate percentage
mldefense_block_rate_percent
```

## Deployment Best Practices

### Initial Deployment

1. **Start in Learning Mode**:
   ```toml
   mldefenseenabled = true
   mldefenselearningmode = true
   mldefenselogsuspicious = true
   ```

2. **Monitor Metrics**: Observe `mldefense_score_distribution` and `mldefense_suspicious_total`

3. **Tune Thresholds**: Adjust based on your traffic patterns

4. **Enable Log-Only Mode**:
   ```toml
   mldefenselearningmode = false
   mldefenseblockmode = false
   ```

5. **Enable Full Blocking**:
   ```toml
   mldefenseblockmode = true
   ```

### Threshold Tuning

- **Conservative** (fewer false positives):
  - Query: 70, Profile: 80, Combined: 90

- **Default** (balanced):
  - Query: 60, Profile: 70, Combined: 80

- **Aggressive** (maximum protection):
  - Query: 50, Profile: 60, Combined: 70

### Production Considerations

- **Performance**: Minimal overhead (~microseconds per query)
- **Memory**: ~100KB per 100 IP profiles
- **Profile TTL**: 30 minutes (automatic cleanup)
- **Max Profiles**: 100,000 (configurable)

## Integration with Existing Security

The ML Defense middleware works alongside existing SDNS security features:

- **Position**: After rate limiting, before EDNS processing
- **Complementary**: Works with access lists, rate limiting, and blocklists
- **Non-Intrusive**: Doesn't interfere with legitimate queries

### Middleware Chain Position

```
1. Recovery
2. Loop Detection
3. Metrics
4. DNSTap
5. Access List
6. Rate Limit
7. ML Defense  ← Positioned here
8. EDNS
9. Access Log
10. ... (other middleware)
```

## Monitoring and Alerting

### Key Metrics to Monitor

1. **Block Rate**: `mldefense_block_rate_percent`
   - Alert if > 5% (may indicate attack or misconfiguration)

2. **Active Profiles**: `mldefense_ip_profiles_active`
   - Alert if approaching max capacity

3. **Suspicious Queries**: `mldefense_suspicious_total`
   - Monitor trends for potential attacks

### Log Analysis

Blocked queries log entries:
```
level=warn msg="ML Defense: Blocked suspicious query"
  remote_ip=192.0.2.1
  query_name=example.com.
  query_type=ANY
  reason=high_query_anomaly_score
  score=85.5
  amplification_factor=179.0
  protocol=udp
```

## Testing

Run the test suite:

```bash
go test ./middleware/mldefense/... -v
```

Test coverage includes:
- Feature extraction
- Anomaly scoring
- IP profiling
- Model decision making
- Profile cleanup

## Limitations

- **Legitimate High-Volume Clients**: May need whitelisting
- **Distributed Attacks**: Per-IP analysis may not catch coordinated attacks
- **Learning Period**: Needs time to establish baselines
- **Configuration Dependent**: Requires tuning for specific environments

## Advanced Configuration

### Disable for Specific Query Types

Modify `HighRiskQueryTypes` in `features.go` to customize detection.

### Custom Amplification Factors

Update `AmplificationFactors` map based on your zone's response sizes.

### Integration with External Systems

Use the `GetStatistics()` API method to export data to external ML systems.

## References

- [US-CERT DNS Amplification Attacks Alert](https://www.us-cert.gov/ncas/alerts/TA13-088A)
- [RFC 5358: Preventing Use of Recursive Nameservers in Reflector Attacks](https://www.rfc-editor.org/rfc/rfc5358.html)
- [RFC 8482: Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY](https://www.rfc-editor.org/rfc/rfc8482.html)

## Support

For issues or questions, please file an issue on the SDNS GitHub repository.

## License

This middleware is part of the SDNS project and follows the same license.
