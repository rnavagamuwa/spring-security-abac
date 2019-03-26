package org.wso2.spring.security.abac;

import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.json.JSONObject;
import org.springframework.util.ResourceUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.wso2.spring.security.abac.cache.Cache;
import org.wso2.spring.security.abac.cache.EhCacheManager;
import org.wso2.spring.security.abac.exception.AttributeEvaluatorException;

import java.io.IOException;
import java.io.StringWriter;
import java.util.Base64;
import java.util.Iterator;
import javax.servlet.http.HttpServletRequest;

/**
 * @author Randika Navagamuwa
 */
public class XacmlAuthRequestBuilder implements AuthRequestBuilder {

    private static String ATTRIBUTE_CONFIG_FILE_NAME = "xacmlConfig.json";

    private Cache<String, String> requestBuilderCache;

    public XacmlAuthRequestBuilder() {

        this.requestBuilderCache = EhCacheManager.getInstance().getCache("requestBuilderCache",
                String.class, String.class, 60, 100);
    }

    @Override
    public String createAuthRequest(String policyName, String jsonKeyValuePairs) {

        String key = Base64.getEncoder().encodeToString(policyName.concat(jsonKeyValuePairs).trim().getBytes());

        String cachedRequest = this.requestBuilderCache.get(key);

        if (cachedRequest != null) {
            return cachedRequest;
        }

        VelocityContext vc = generateVelocityData(jsonKeyValuePairs);

        String xacmlRequest;
        try {

            VelocityEngine velocityEngine = new VelocityEngine();
            velocityEngine.setProperty(RuntimeConstants.FILE_RESOURCE_LOADER_PATH,
                    ResourceUtils.getFile("classpath:" + ATTRIBUTE_CONFIG_FILE_NAME).getParent());
            Template template = velocityEngine.getTemplate(ATTRIBUTE_CONFIG_FILE_NAME);
            velocityEngine.init();

            StringWriter writer = new StringWriter();
            template.merge(vc, writer);

            xacmlRequest = new JSONObject(writer.toString()).get(policyName).toString();

        } catch (IOException e) {

            throw new AttributeEvaluatorException("Failed to build the XACML Json request for policy with name : " +
                    policyName, e);
        }

        if (xacmlRequest == null || xacmlRequest.isEmpty()) {

            throw new AttributeEvaluatorException("Generated XACML request is empty or NULL for policy with name : " +
                    policyName);
        }

        return this.requestBuilderCache.putIfAbsent(key, xacmlRequest);
    }

    private VelocityContext generateVelocityData(String jsonKeyValuePairs) {

        JSONObject jsonObject = new JSONObject(jsonKeyValuePairs.trim());

        Iterator<String> keys = jsonObject.keys();

        ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes)
                RequestContextHolder.currentRequestAttributes();
        HttpServletRequest httpServletRequest = servletRequestAttributes.getRequest();

        VelocityContext velocityContext = new VelocityContext();

        while (keys.hasNext()) {
            String key = keys.next();
            String value = jsonObject.get(key).toString();
            velocityContext.put(key, httpServletRequest.getHeader(value));
        }

        return velocityContext;
    }

}
