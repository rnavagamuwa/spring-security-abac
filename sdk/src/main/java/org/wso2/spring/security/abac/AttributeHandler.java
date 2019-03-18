package org.wso2.spring.security.abac;

/**
 * @author Randika Navagamuwa
 */
public interface AttributeHandler {

    boolean authorize(String policyRequest);

}
