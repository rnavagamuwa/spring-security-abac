package org.wso2.spring.security.abac;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import org.wso2.spring.security.abac.cache.CacheManager;
import org.wso2.spring.security.abac.cache.EhCacheManager;
import org.wso2.spring.security.abac.exception.AttributeEvaluatorException;

import java.io.IOException;
import java.util.Collections;

/**
 * @author Randika Navagamuwa
 */
@SuppressWarnings("WeakerAccess")
public class XacmlAttributeHandler implements AttributeHandler {

    private static String XACML_PDP_URL;
    private CacheManager cacheManager;

    public XacmlAttributeHandler() {

        try {
            XACML_PDP_URL = PropertiesLoaderUtils
                    .loadAllProperties("application.properties")
                    .getProperty("xacml.pdp.url");
        } catch (IOException e) {

            //todo stop the whole app
            throw new AttributeEvaluatorException("Failed to read the XACML PDP Url", e);
        }

        if (XACML_PDP_URL == null) {
            //todo stop the whole app
        }

        this.cacheManager = new EhCacheManager();
    }

    @Override
    public boolean authorize(String authRequest) {

        String cachedResponse = this.cacheManager.get(authRequest);

        if (cachedResponse == null) {
            RestTemplate restTemplate = new RestTemplate();

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
            headers.setBasicAuth("admin", "admin");

            HttpEntity<String> entity = new HttpEntity<>(authRequest, headers);

            ResponseEntity response = restTemplate.postForEntity(XACML_PDP_URL, entity, String.class);
            if (response.getBody() == null) {
                return false;
            }
            cachedResponse = response.getBody().toString();
            this.cacheManager.putIfAbsent(authRequest, cachedResponse);
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

}
