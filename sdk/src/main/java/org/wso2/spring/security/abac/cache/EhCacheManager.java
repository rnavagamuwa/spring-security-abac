package org.wso2.spring.security.abac.cache;

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

    private static long EXPIRY_IN_MINUTUES = 60;
    private static long MAX_ENTRIES = 100;

    private CacheManager cacheManager;

    private EhCacheManager() {

        cacheManager = CacheManagerBuilder.newCacheManagerBuilder().build();
        cacheManager.init();

    }

    public static org.wso2.spring.security.abac.cache.CacheManager getInstance() {

        return new EhCacheManager();
    }

    @Override
    public Cache getCache(String cacheName, Class<?> key, Class<?> value, long expiryInMuntues, long maxEntries) {

        return new EhCache(cacheManager.createCache(cacheName, CacheConfigurationBuilder
                .newCacheConfigurationBuilder(key, value, ResourcePoolsBuilder.heap(maxEntries))
                .withExpiry(ExpiryPolicyBuilder.timeToLiveExpiration(Duration.ofMinutes(expiryInMuntues)))
                .build()));
    }
}
