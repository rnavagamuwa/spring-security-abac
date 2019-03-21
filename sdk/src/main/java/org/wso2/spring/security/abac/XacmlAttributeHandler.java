package org.wso2.spring.security.abac;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.util.ResourceUtils;
import org.springframework.web.client.RestTemplate;
import org.wso2.spring.security.abac.cache.CacheManager;
import org.wso2.spring.security.abac.cache.EhCacheManager;
import org.wso2.spring.security.abac.exception.AttributeEvaluatorException;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Collections;
import java.util.Optional;
import java.util.Properties;
import javax.net.ssl.SSLContext;

/**
 * @author Randika Navagamuwa
 */
@SuppressWarnings("WeakerAccess")
public class XacmlAttributeHandler implements AttributeHandler {

    private static String XACML_PDP_AUTHORIZE_URL;
    private static String XACML_PDP_RESOURCE_LIST_URL;
    private static String TRUST_STORE;
    private static String TRUST_STORE_PASSWORD;
    private static String KEY_STORE;
    private static String KEY_STORE_PASSWORD;

    private CacheManager responseCacheManager;
    private SSLContext sslContext;
    private HttpHeaders headers;

    public XacmlAttributeHandler() {

        try {
            Properties properties = PropertiesLoaderUtils
                    .loadAllProperties("application.properties");
            XACML_PDP_AUTHORIZE_URL = properties.getProperty("xacml.pdp.url.authorize");
            XACML_PDP_RESOURCE_LIST_URL = properties.getProperty("xacml.pdp.url.resourceList");
            TRUST_STORE = properties.getProperty("xacml.pdp.trustStore");
            TRUST_STORE_PASSWORD = properties.getProperty("xacml.pdp.trustStore.password");
            KEY_STORE = properties.getProperty("xacml.pdp.keyStore");
            KEY_STORE_PASSWORD = properties.getProperty("xacml.pdp.keyStore.password");
        } catch (IOException e) {

            //todo stop the whole app
            throw new AttributeEvaluatorException("Failed to read the XACML PDP Url", e);
        }

        if (XACML_PDP_AUTHORIZE_URL == null) {
            //todo stop the whole app
        }

        try {
            this.sslContext = SSLContextBuilder
                    .create()
                    .loadKeyMaterial(loadPfx("classpath:".concat(KEY_STORE), KEY_STORE_PASSWORD.toCharArray()),
                            KEY_STORE_PASSWORD.toCharArray())
                    .loadTrustMaterial(ResourceUtils.getFile("classpath:".concat(TRUST_STORE)),
                            TRUST_STORE_PASSWORD.toCharArray())
                    .build();
        } catch (Exception e) {

            //todo stop the whole app
            throw new AttributeEvaluatorException("Failed to read keystore or truststore", e);
        }

        this.headers = new HttpHeaders();
        this.headers.setContentType(MediaType.APPLICATION_JSON);
        this.headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        this.headers.set("WSO2-Identity-User", "admin");

        this.responseCacheManager = new EhCacheManager();
    }

    @Override
    public boolean authorize(String authRequest) {

        String cachedResponse = this.responseCacheManager.get(authRequest);

        if (cachedResponse == null) {

            HttpClient client = HttpClients.custom()
                    .setSSLContext(sslContext)
                    .build();

            RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder().requestFactory(() ->
                    new HttpComponentsClientHttpRequestFactory(client));
            RestTemplate rt = restTemplateBuilder.build();

            HttpEntity<String> entity = new HttpEntity<>(authRequest, this.headers);

            ResponseEntity response = rt.postForEntity(XACML_PDP_AUTHORIZE_URL, entity, String.class);
            if (response.getStatusCode() != HttpStatus.OK || response.getBody() == null) {
                return false;
            }
            cachedResponse = response.getBody().toString();
            this.responseCacheManager.putIfAbsent(authRequest, cachedResponse);
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

        String cachedResponse = this.responseCacheManager.get(XACML_PDP_RESOURCE_LIST_URL);

        if (cachedResponse == null) {

            HttpClient client = HttpClients.custom()
                    .setSSLContext(sslContext)
                    .build();

            RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder().requestFactory(() ->
                    new HttpComponentsClientHttpRequestFactory(client));
            RestTemplate rt = restTemplateBuilder.build();

            HttpEntity<String> entity = new HttpEntity<>(this.headers);

            ResponseEntity response = rt.getForEntity(XACML_PDP_RESOURCE_LIST_URL, String.class, entity);

            if (response.getStatusCode() != HttpStatus.OK || response.getBody() == null) {

                return Optional.empty();
            }
            cachedResponse = response.getBody().toString();
            this.responseCacheManager.putIfAbsent(XACML_PDP_RESOURCE_LIST_URL, cachedResponse);
        }
        return Optional.of(new JSONObject(cachedResponse));
    }

    private KeyStore loadPfx(String file, char[] password) throws Exception {

        KeyStore keyStore = KeyStore.getInstance("JKS");
        File key = ResourceUtils.getFile(file);
        try (InputStream in = new FileInputStream(key)) {
            keyStore.load(in, password);
        }
        return keyStore;
    }

}
