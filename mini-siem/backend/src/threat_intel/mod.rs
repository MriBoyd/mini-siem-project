pub struct ThreatIntelFeed {
    provider: ThreatIntelProvider,
    cache: RedisCache,
}

impl ThreatIntelFeed {
    pub async fn check_ip(&self, ip: &str) -> Result<ThreatScore> {
        // Check cache first
        if let Some(score) = self.cache.get_ip_reputation(ip).await? {
            return Ok(ThreatScore { score, cached: true });
        }
        
        // Query external API (AlienVault OTX, VirusTotal, etc.)
        let score = self.provider.query_ip(ip).await?;
        
        // Cache for 1 hour
        self.cache.set_ip_reputation(ip, score.score, 3600).await?;
        
        Ok(score)
    }
}