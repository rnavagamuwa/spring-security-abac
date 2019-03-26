package org.wso2.spring.security.abac.cache;

/**
 * @author Randika Navagamuwa
 */
public class EhCache implements Cache {

    private org.ehcache.Cache cache;

    public EhCache(org.ehcache.Cache cache) {

        this.cache = cache;
    }

    public org.ehcache.Cache getCache() {

        return this.cache;
    }

    @Override
    public Object get(Object key) {

        return this.cache.get(key);
    }

    @Override
    public Object putIfAbsent(Object key, Object value) {

        return this.cache.putIfAbsent(key, value);
    }
}
