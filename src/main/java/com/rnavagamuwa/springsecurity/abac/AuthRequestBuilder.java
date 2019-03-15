package com.rnavagamuwa.springsecurity.abac;

/**
 * @author Randika Navagamuwa
 */
public interface AuthRequestBuilder {

    String createAuthRequest(String policyName, String jsonKeyValuePairs);
}
