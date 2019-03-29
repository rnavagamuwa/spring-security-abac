package org.wso2.spring.security.abac.util;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.Version;
import org.json.JSONObject;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.wso2.spring.security.abac.cache.Cache;
import org.wso2.spring.security.abac.cache.EhCacheManager;
import org.wso2.spring.security.abac.exception.AttributeEvaluatorException;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.StringWriter;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

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

        String xacmlRequest;
        try (StringWriter out = new StringWriter()) {

            Configuration cfg = new Configuration(new Version("2.3.23"));

            cfg.setClassForTemplateLoading(this.getClass(), "/");
            cfg.setDefaultEncoding("UTF-8");

            Template template = cfg.getTemplate(ATTRIBUTE_CONFIG_FILE_NAME);

            Map<String, Object> templateData = generateFreemakeTemplateData(jsonKeyValuePairs);

            template.process(templateData, out);
            xacmlRequest = new JSONObject(out.toString()).get(policyName).toString();

            out.flush();


        } catch (IOException | TemplateException e) {

            throw new AttributeEvaluatorException("Failed to build the XACML Json request for policy with name : " +
                    policyName, e);

        }

        if (xacmlRequest == null || xacmlRequest.isEmpty()) {

            throw new AttributeEvaluatorException("Generated XACML request is empty or NULL for policy with name : " +
                    policyName);
        }

        return this.requestBuilderCache.putIfAbsent(key, xacmlRequest);
    }

    private Map<String, Object> generateFreemakeTemplateData(String jsonKeyValuePairs) {
        JSONObject jsonObject = new JSONObject(jsonKeyValuePairs.trim());

        Iterator<String> keys = jsonObject.keys();

        ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes)
                RequestContextHolder.currentRequestAttributes();
        HttpServletRequest httpServletRequest = servletRequestAttributes.getRequest();

        Map<String, Object> templateData = new HashMap<>();

        while (keys.hasNext()) {
            String key = keys.next();
            String value = jsonObject.get(key).toString();
            templateData.put(key, httpServletRequest.getHeader(value));
        }

        return templateData;
    }

}
