package org.wso2.spring.security.abac.cache;

import org.ehcache.Cache;
import org.ehcache.CacheManager;
import org.ehcache.config.builders.CacheConfigurationBuilder;
import org.ehcache.config.builders.CacheManagerBuilder;
import org.ehcache.config.builders.ExpiryPolicyBuilder;
import org.ehcache.config.builders.ResourcePoolsBuilder;

import java.time.Duration;

/**
 * @author Randika Navagamuwa
 */
public class EhCacheManager implements org.wso2.spring.security.abac.cache.CacheManager {

    private static String CACHE_NAME = "policyRequestCache";
    private static long EXPIRY_IN_MINUTUES = 60;
    private static long MAX_ENTRIES = 100;

    private CacheManager cacheManager;
    private Cache<String, String> responseCache;

    public EhCacheManager() {

        cacheManager = CacheManagerBuilder.newCacheManagerBuilder().build();
        cacheManager.init();

        responseCache = cacheManager.createCache(CACHE_NAME, CacheConfigurationBuilder
                .newCacheConfigurationBuilder(String.class, String.class, ResourcePoolsBuilder.heap(MAX_ENTRIES))
                .withExpiry(ExpiryPolicyBuilder.timeToLiveExpiration(Duration.ofMinutes(EXPIRY_IN_MINUTUES)))
                .build());
    }

    public String get(String cahceKey) {

        return this.responseCache.get(cahceKey);
    }

    public String putIfAbsent(String key, String value) {

        return this.responseCache.putIfAbsent(key, value);
    }
}
