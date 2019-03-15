package com.rnavagamuwa.springsecurity.abac.cache;

/**
 * @author Randika Navagamuwa
 */
public interface CacheManager {

    String get(String cahceKey);

    String putIfAbsent(String key, String value);
}
