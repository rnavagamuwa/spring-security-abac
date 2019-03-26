package org.wso2.spring.security.abac;

import org.apache.http.Header;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.ssl.SSLContextBuilder;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.util.ResourceUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.ws.transport.http.HttpComponentsMessageSender;
import org.wso2.spring.security.abac.cache.Cache;
import org.wso2.spring.security.abac.cache.CacheManager;
import org.wso2.spring.security.abac.cache.EhCacheManager;
import org.wso2.spring.security.abac.soaputils.CustomSSLHttpClientFactory;
import org.wso2.spring.security.abac.soaputils.EntitlementServiceClient;
import org.wso2.spring.security.abac.soaputils.wsdl.EntitledResultSetDTO;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import javax.net.ssl.SSLContext;
import javax.xml.bind.JAXBElement;

/**
 * @author Randika Navagamuwa
 */
@SuppressWarnings("WeakerAccess")
public class XacmlAttributeHandler implements AttributeHandler {

    private static final Logger logger = LoggerFactory.getLogger(XacmlAttributeHandler.class);

    private static String XACML_PDP_AUTHORIZE_URL;
    private static String XACML_PDP_RESOURCE_LIST_URL;
    private static String XACML_PDP_ENTITLEMENT_SERVICE_URL;
    private static String TRUST_STORE;
    private static String TRUST_STORE_PASSWORD;
    private static String KEY_STORE;
    private static String KEY_STORE_PASSWORD;
    private static String CERT_ALIAS;

    private SSLContext sslContext;
    private HttpHeaders restHeaders;
    private List<Header> soapHeaders;
    private CustomSSLHttpClientFactory customSSLHttpClientFactory;
    private EntitlementServiceClient entitlementServiceClient;

    private Cache<String, String> authCache;
    private Cache<String, JAXBElement<EntitledResultSetDTO>> entitlementServiceCache;
    private Cache<String, JSONObject> apiResourceListCache;

    public XacmlAttributeHandler() {

        try {
            Properties properties = PropertiesLoaderUtils
                    .loadAllProperties("application.properties");
            XACML_PDP_AUTHORIZE_URL = properties.getProperty("xacml.pdp.url.authorize");
            XACML_PDP_RESOURCE_LIST_URL = properties.getProperty("xacml.pdp.url.resource.list");
            XACML_PDP_ENTITLEMENT_SERVICE_URL = properties.getProperty("xacml.pdp.url.entitlement.service");
            TRUST_STORE = properties.getProperty("xacml.pdp.trustStore");
            TRUST_STORE_PASSWORD = properties.getProperty("xacml.pdp.trustStore.password");
            KEY_STORE = properties.getProperty("xacml.pdp.keyStore");
            KEY_STORE_PASSWORD = properties.getProperty("xacml.pdp.keyStore.password");
            CERT_ALIAS = properties.getProperty("xacml.pdp.keyStore.cert.alias");

        } catch (IOException e) {

            logger.error("Failed to read properties from application.properties", e);
            stopApplication();
        }

        if (XACML_PDP_AUTHORIZE_URL == null) {

            logger.error("xacml.pdp.url.authorize property is null null in application.properties");
            stopApplication();
        }

        if (XACML_PDP_RESOURCE_LIST_URL == null) {

            logger.error("xacml.pdp.url.resource.list property is null in application.properties");
            stopApplication();
        }

        if (XACML_PDP_ENTITLEMENT_SERVICE_URL == null) {

            logger.error("xacml.pdp.url.entitlement.service property is null in application.properties");
            stopApplication();
        }

        try {
            this.sslContext = SSLContextBuilder
                    .create()
                    .loadKeyMaterial(loadPfx("classpath:".concat(KEY_STORE), KEY_STORE_PASSWORD.toCharArray()),
                            KEY_STORE_PASSWORD.toCharArray())
                    .loadTrustMaterial(ResourceUtils.getFile("classpath:".concat(TRUST_STORE)),
                            TRUST_STORE_PASSWORD.toCharArray())
                    .build();

            this.customSSLHttpClientFactory = new CustomSSLHttpClientFactory(
                    new FileSystemResource(ResourceUtils.getFile("classpath:".concat(KEY_STORE))),
                    KEY_STORE_PASSWORD,
                    "JKS",
                    new FileSystemResource(ResourceUtils.getFile("classpath:".concat(TRUST_STORE))),
                    TRUST_STORE_PASSWORD,
                    new String[]{"TLSv1"},
                    CERT_ALIAS);

            this.soapHeaders = new ArrayList<>();
            //todo use mutual SSL
            soapHeaders.add(new BasicHeader("Authorization", "Basic YWRtaW46YWRtaW4="));

            CacheManager cacheManager = EhCacheManager.getInstance();
            this.authCache = cacheManager.getCache("authCache", String.class, String.class, 60, 100);
            this.entitlementServiceCache = cacheManager.getCache("entitlementCache", String.class, JAXBElement.class, 60, 100);
            this.apiResourceListCache = cacheManager.getCache("apiResourceList", String.class, JSONObject.class, 60, 100);

            Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
            marshaller.setContextPath("org.wso2.spring.security.abac.soaputils.wsdl");

            this.entitlementServiceClient = new EntitlementServiceClient(XACML_PDP_ENTITLEMENT_SERVICE_URL);
            this.entitlementServiceClient.setMarshaller(marshaller);
            this.entitlementServiceClient.setUnmarshaller(marshaller);
            this.entitlementServiceClient.setMessageSender(new HttpComponentsMessageSender(
                    HttpClientBuilder
                            .create()
                            .setSSLSocketFactory(new SSLConnectionSocketFactory(this.sslContext, NoopHostnameVerifier.INSTANCE))
                            .addInterceptorFirst(new HttpComponentsMessageSender.RemoveSoapHeadersInterceptor())
                            .setDefaultHeaders(this.soapHeaders)
                            .build()));
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

            HttpClient client = HttpClients.custom()
                    .setSSLContext(sslContext)
                    .build();

            RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder().requestFactory(() ->
                    new HttpComponentsClientHttpRequestFactory(client));
            RestTemplate rt = restTemplateBuilder.build();

            HttpEntity<String> entity = new HttpEntity<>(authRequest, this.restHeaders);

            ResponseEntity response = rt.postForEntity(XACML_PDP_AUTHORIZE_URL, entity, String.class);
            if (response.getStatusCode() != HttpStatus.OK || response.getBody() == null) {
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

        JSONObject cachedObject = this.apiResourceListCache.get(XACML_PDP_RESOURCE_LIST_URL);

        if (cachedObject != null) {

            return Optional.of(cachedObject);
        }

        HttpClient client = HttpClients.custom()
                .setSSLContext(sslContext)
                .build();

        RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder().requestFactory(() ->
                new HttpComponentsClientHttpRequestFactory(client));
        RestTemplate rt = restTemplateBuilder.build();

        HttpEntity<String> entity = new HttpEntity<>(this.restHeaders);

        ResponseEntity response = rt.getForEntity(XACML_PDP_RESOURCE_LIST_URL, String.class, entity);

        if (response.getStatusCode() != HttpStatus.OK || response.getBody() == null) {

            return Optional.empty();
        }

        return Optional.of(this.apiResourceListCache.putIfAbsent(XACML_PDP_RESOURCE_LIST_URL,
                new JSONObject(response.getBody().toString())));

    }

    @Override
    public JAXBElement<EntitledResultSetDTO> getEntitledAttributes(String subjectName, String resourceName,
                                                                   String subjectId, String action,
                                                                   boolean enableChildSearch) {

        String key = Base64
                .getEncoder()
                .encodeToString(subjectName
                        .concat(resourceName)
                        .concat(subjectId)
                        .concat(action)
                        .concat(String.valueOf(enableChildSearch)).getBytes());

        JAXBElement<EntitledResultSetDTO> resultSet = this.entitlementServiceCache.get(key);

        if (resultSet != null) {
            return resultSet;
        }

        return this.entitlementServiceCache.putIfAbsent(key, this.entitlementServiceClient.
                getEntitledAttributes(subjectName, resourceName, subjectId, action, enableChildSearch).getReturn());

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
