package org.wso2.spring.security.abac.cache;

/**
 * @author Randika Navagamuwa
 */
public interface CacheManager {

    Cache getCache(String cacheName, Class<?> key, Class<?> value, long expiryInMuntues, long maxEntries);
}
