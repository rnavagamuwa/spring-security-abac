package org.wso2.spring.security.abac.util;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.Version;
import org.json.JSONObject;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.HandlerMapping;
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

        Map<String, Object> templateData = generateFreemakeTemplateData(jsonKeyValuePairs);

        String key = Base64.getEncoder().encodeToString(policyName
                .concat(jsonKeyValuePairs)
                .concat(getTemplateDataAsAString(templateData)).trim().getBytes());

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
            String[] proTypeArr = value.split("\\.", 2);

            PropertyType propertyType = PropertyType.getEnum(proTypeArr[0]);
            if (!proTypeArr[0].isEmpty()) {
                value = proTypeArr[1];
            }

            switch (propertyType) {
                case HEADER:
                    value = httpServletRequest.getHeader(value);
                    break;
                case COOKIE:
                    value = GeneralUtils.extractValuesFromCookies(httpServletRequest.getCookies()).get(value);
                    break;
                case QUERY_PARAM:
                    value = httpServletRequest.getParameter(value);
                    break;
                case FORM_DATA:
                    value = httpServletRequest.getParameter(value);
                    break;
                case PATH_PARAM:
                    value = extractPathParam(httpServletRequest,value);
                    break;
            }
            templateData.put(key, value);
        }

        return templateData;
    }

    private String extractPathParam(HttpServletRequest httpServletRequest, String key) {
        Map paramsMap = (Map) httpServletRequest.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
        return (String) paramsMap.get(key);
    }

    private String getTemplateDataAsAString(Map<String, Object> templateData) {

        StringBuilder stringBuilder = new StringBuilder();
        for (Map.Entry<String, Object> entry : templateData.entrySet()) {
            stringBuilder.append(entry.getKey()).append(entry.getValue());
        }

        return stringBuilder.toString();

    }

    private enum PropertyType {
        HEADER("header"),
        QUERY_PARAM("queryParam"),
        COOKIE("cookie"),
        FORM_DATA("formdata"),
        PATH_PARAM("pathParam");

        private String property;

        PropertyType(String property) {
            this.property = property;
        }

        @Override
        public String toString() {
            return this.property;
        }

        public static PropertyType getEnum(String property) {
            for (PropertyType v : values())
                if (v.toString().equalsIgnoreCase(property)) return v;
            return PropertyType.HEADER;
        }
    }

}
