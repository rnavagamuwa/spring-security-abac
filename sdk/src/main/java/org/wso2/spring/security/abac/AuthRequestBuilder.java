package org.wso2.spring.security.abac;

/**
 * @author Randika Navagamuwa
 */
public interface AuthRequestBuilder {

    String createAuthRequest(String policyName, String jsonKeyValuePairs);
}
