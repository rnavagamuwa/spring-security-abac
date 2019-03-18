package org.wso2.spring.security.abac.cache;

/**
 * @author Randika Navagamuwa
 */
public interface CacheManager {

    String get(String cahceKey);

    String putIfAbsent(String key, String value);
}
