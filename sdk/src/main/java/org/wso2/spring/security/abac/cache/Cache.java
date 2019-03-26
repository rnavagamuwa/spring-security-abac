package org.wso2.spring.security.abac.cache;

/**
 * @author Randika Navagamuwa
 */
public interface Cache<K, V> {

    V get(K key);

    V putIfAbsent(K key, V value);
}
