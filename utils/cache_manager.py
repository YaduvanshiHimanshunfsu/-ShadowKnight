"""
Cache Manager
Optimize Gemini API usage through intelligent caching
"""

import json
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from pathlib import Path


class CacheManager:
    """
    Cache Gemini API responses to reduce costs and improve performance
    """
    
    def __init__(self, cache_dir: str = "./cache", ttl_seconds: int = 3600):
        """
        Initialize Cache Manager
        
        Args:
            cache_dir: Directory for cache storage
            ttl_seconds: Time-to-live for cache entries (default 1 hour)
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_seconds
        
        # In-memory cache for frequently accessed items
        self.memory_cache: Dict[str, Dict[str, Any]] = {}
        
        # Rate limiting
        self.api_calls = []
        self.max_calls_per_minute = 30
        # Per-key API usage tracking removed (reverting changes)
    
    def get_cached_response(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """
        Get cached response if available and not expired
        
        Args:
            cache_key: Cache key
        
        Returns:
            Cached response or None
        """
        # Check memory cache first
        if cache_key in self.memory_cache:
            entry = self.memory_cache[cache_key]
            if not self._is_expired(entry['timestamp']):
                entry['cache_hits'] = entry.get('cache_hits', 0) + 1
                return entry['response']
        
        # Check disk cache
        cache_file = self.cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    entry = json.load(f)
                
                if not self._is_expired(entry['timestamp']):
                    # Load into memory cache
                    self.memory_cache[cache_key] = entry
                    entry['cache_hits'] = entry.get('cache_hits', 0) + 1
                    return entry['response']
                else:
                    # Remove expired cache
                    cache_file.unlink()
            except Exception:
                pass
        
        return None
    
    def cache_response(self, cache_key: str, response: Dict[str, Any]):
        """
        Cache API response
        
        Args:
            cache_key: Cache key
            response: Response to cache
        """
        entry = {
            'timestamp': datetime.now().isoformat(),
            'response': response,
            'cache_hits': 0
        }
        
        # Store in memory cache
        self.memory_cache[cache_key] = entry
        
        # Store on disk
        cache_file = self.cache_dir / f"{cache_key}.json"
        with open(cache_file, 'w') as f:
            json.dump(entry, f, indent=2)
    
    def generate_cache_key(self, *args, **kwargs) -> str:
        """
        Generate cache key from arguments
        
        Args:
            *args: Positional arguments
            **kwargs: Keyword arguments
        
        Returns:
            Cache key hash
        """
        # Create deterministic string from arguments
        cache_string = json.dumps({
            'args': args,
            'kwargs': kwargs
        }, sort_keys=True)
        
        # Generate hash
        return hashlib.md5(cache_string.encode()).hexdigest()
    
    def _is_expired(self, timestamp_str: str) -> bool:
        """Check if cache entry is expired"""
        try:
            timestamp = datetime.fromisoformat(timestamp_str)
            age = datetime.now() - timestamp
            return age.total_seconds() > self.ttl_seconds
        except Exception:
            return True
    
    def clear_cache(self):
        """Clear all cache"""
        self.memory_cache.clear()
        
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()
    
    def clear_expired_cache(self):
        """Remove expired cache entries"""
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, 'r') as f:
                    entry = json.load(f)
                
                if self._is_expired(entry['timestamp']):
                    cache_file.unlink()
            except Exception:
                pass
    
    def check_rate_limit(self) -> bool:
        """
        Check if API call is within rate limit
        
        Returns:
            True if within limit, False if rate limited
        """
        now = time.time()
        
        # Remove calls older than 1 minute
        self.api_calls = [t for t in self.api_calls if now - t < 60]
        
        # Check limit
        if len(self.api_calls) >= self.max_calls_per_minute:
            return False
        
        # Record this call
        self.api_calls.append(now)
        return True
    
    def wait_for_rate_limit(self):
        """Wait until rate limit allows next call"""
        while not self.check_rate_limit():
            time.sleep(1)
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_entries = len(list(self.cache_dir.glob("*.json")))
        memory_entries = len(self.memory_cache)
        
        total_hits = sum(entry.get('cache_hits', 0) for entry in self.memory_cache.values())
        
        return {
            'total_cache_entries': total_entries,
            'memory_cache_entries': memory_entries,
            'total_cache_hits': total_hits,
            'cache_directory': str(self.cache_dir),
            'ttl_seconds': self.ttl_seconds,
            'api_calls_last_minute': len(self.api_calls)
        }
    
    def get_cache_efficiency(self) -> float:
        """
        Calculate cache hit rate
        
        Returns:
            Cache hit rate (0.0 to 1.0)
        """
        if not self.memory_cache:
            return 0.0
        
        total_hits = sum(entry.get('cache_hits', 0) for entry in self.memory_cache.values())
        total_entries = len(self.memory_cache)
        
        if total_entries == 0:
            return 0.0
        
        return total_hits / (total_hits + total_entries)
