package org.wso2.spring.security.abac;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.http.*;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.util.ResourceUtils;
import org.springframework.web.client.RestTemplate;
import org.wso2.spring.security.abac.cache.Cache;
import org.wso2.spring.security.abac.cache.CacheManager;
import org.wso2.spring.security.abac.cache.EhCacheManager;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Base64;
import java.util.Collections;
import java.util.Optional;
import java.util.Properties;

/**
 * @author Randika Navagamuwa
 */
@SuppressWarnings("WeakerAccess")
public class XacmlAttributeHandler implements AttributeHandler {

    private static final Logger logger = LoggerFactory.getLogger(XacmlAttributeHandler.class);

    private static String XACML_PDP_ENTITLEMENT_SERVICE_URL;
    private static String TRUST_STORE;
    private static String TRUST_STORE_PASSWORD;
    private static String KEY_STORE;
    private static String KEY_STORE_PASSWORD;

    protected HttpClient httpClient;
    private HttpHeaders restHeaders;

    private Cache<String, String> authCache;
    private Cache<String, JSONObject> entitlementAttributesCache;
    private Cache<String, JSONObject> apiResourceListCache;

    public XacmlAttributeHandler() {

        try {
            Properties properties = PropertiesLoaderUtils
                    .loadAllProperties("application.properties");
            XACML_PDP_ENTITLEMENT_SERVICE_URL = properties.getProperty("xacml.pdp.url.entitlement.service");
            TRUST_STORE = properties.getProperty("xacml.pdp.trustStore");
            TRUST_STORE_PASSWORD = properties.getProperty("xacml.pdp.trustStore.password");
            KEY_STORE = properties.getProperty("xacml.pdp.keyStore");
            KEY_STORE_PASSWORD = properties.getProperty("xacml.pdp.keyStore.password");

        } catch (IOException e) {

            logger.error("Failed to read properties from application.properties", e);
            stopApplication();
        }

        if (XACML_PDP_ENTITLEMENT_SERVICE_URL == null) {

            logger.error("xacml.pdp.url.entitlement.service property is null in application.properties");
            stopApplication();
        }

        CacheManager cacheManager = EhCacheManager.getInstance();
        this.authCache = cacheManager.getCache("authCache", String.class, String.class, 60, 100);
        this.entitlementAttributesCache = cacheManager.getCache("entitlementCache", String.class, JSONObject.class, 60, 100);
        this.apiResourceListCache = cacheManager.getCache("apiResourceList", String.class, JSONObject.class, 60, 100);

        try {

            this.httpClient = HttpClients
                    .custom()
                    .setSSLContext(SSLContextBuilder
                            .create()
                            .loadKeyMaterial(loadPfx("classpath:".concat(KEY_STORE), KEY_STORE_PASSWORD.toCharArray()),
                                    KEY_STORE_PASSWORD.toCharArray())
                            .loadTrustMaterial(ResourceUtils.getFile("classpath:".concat(TRUST_STORE)),
                                    TRUST_STORE_PASSWORD.toCharArray())
                            .build())
                    .build();

        } catch (Exception e) {

            logger.error("Failed to read trustStore/keyStore", e);
            SpringApplication.run(XacmlAttributeHandler.class).close();
        }

        this.restHeaders = new HttpHeaders();
        this.restHeaders.setContentType(MediaType.APPLICATION_JSON);
        this.restHeaders.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        this.restHeaders.set("WSO2-Identity-User", "admin");

        logger.info("XacmlAttributeHandler successfully initiated");
    }

    @Override
    public boolean authorize(String authRequest) {

        String cachedResponse = this.authCache.get(authRequest);

        if (cachedResponse == null) {

            RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder().requestFactory(() ->
                    new HttpComponentsClientHttpRequestFactory(this.httpClient));
            RestTemplate rt = restTemplateBuilder.build();

            HttpEntity<String> entity = new HttpEntity<>(authRequest, this.restHeaders);

            ResponseEntity response = rt.postForEntity(XACML_PDP_ENTITLEMENT_SERVICE_URL + "/pdp", entity, String.class);
            if (response.getStatusCode() != HttpStatus.OK) {
                return false;
            }
            cachedResponse = response.getBody().toString();
            this.authCache.putIfAbsent(authRequest, cachedResponse);
        }

        JSONObject responseObj = new JSONObject(cachedResponse);
        JSONArray responseDataArr = responseObj.getJSONArray("Response");

        if (responseDataArr.isEmpty()) {
            return false;
        }

        for (Object Response : responseDataArr) {
            JSONObject currentResponse = (JSONObject) Response;
            if (!currentResponse.getString("Decision").equals("Permit")) {
                return false;
            }
        }
        return true;
    }

    @Override
    public Optional<JSONObject> getApiResourceList() {

        JSONObject cachedObject = this.apiResourceListCache.get(XACML_PDP_ENTITLEMENT_SERVICE_URL + "/home");

        if (cachedObject != null) {

            return Optional.of(cachedObject);
        }

        RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder().requestFactory(() ->
                new HttpComponentsClientHttpRequestFactory(this.httpClient));
        RestTemplate rt = restTemplateBuilder.build();

        HttpEntity<String> entity = new HttpEntity<>(this.restHeaders);

        ResponseEntity response = rt.getForEntity(XACML_PDP_ENTITLEMENT_SERVICE_URL + "/home", String.class, entity);

        if (response.getStatusCode() != HttpStatus.OK) {

            return Optional.empty();
        }

        return Optional.of(this.apiResourceListCache.putIfAbsent(XACML_PDP_ENTITLEMENT_SERVICE_URL + "/home",
                new JSONObject(response.getBody().toString())));

    }

    @Override
    public Optional<JSONObject> getEntitledAttributes(String subjectName, String resourceName,
                                                      String subjectId, String action,
                                                      boolean enableChildSearch) {

        String key = Base64
                .getEncoder()
                .encodeToString(subjectName
                        .concat(resourceName)
                        .concat(subjectId)
                        .concat(action)
                        .concat(String.valueOf(enableChildSearch)).getBytes());

        JSONObject resultSet = this.entitlementAttributesCache.get(key);

        if (resultSet != null) {
            return Optional.of(resultSet);
        }

        String jsonRequest = "{\n" +
                "  \"subjectName\" : \"" + subjectName + "\",\n" +
                "  \"resourceName\": \"" + resourceName + "\",\n" +
                "  \"enableChildSearch\" : \"" + enableChildSearch + "\",\n" +
                "  \"subjectId\":\"" + subjectId + "\",\n" +
                "  \"action\":\"" + action + "\"\n" +
                "  \n" +
                "}";

        RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder().requestFactory(() ->
                new HttpComponentsClientHttpRequestFactory(this.httpClient));
        RestTemplate rt = restTemplateBuilder.build();

        HttpEntity<String> entity = new HttpEntity<>(jsonRequest, this.restHeaders);

        ResponseEntity response = rt.postForEntity(XACML_PDP_ENTITLEMENT_SERVICE_URL + "/entitled-attribs", entity, String.class);

        if (response.getStatusCode() != HttpStatus.OK || response.getBody() == null) {
            return Optional.empty();
        }

        return Optional.of(this.entitlementAttributesCache.putIfAbsent(key, new JSONObject(response.getBody().toString())));

    }

    private KeyStore loadPfx(String file, char[] password) throws Exception {

        KeyStore keyStore = KeyStore.getInstance("JKS");
        File key = ResourceUtils.getFile(file);
        try (InputStream in = new FileInputStream(key)) {
            keyStore.load(in, password);
        }
        return keyStore;
    }

    private static void stopApplication() {

        SpringApplication.run(XacmlAttributeHandler.class).close();
    }

}
