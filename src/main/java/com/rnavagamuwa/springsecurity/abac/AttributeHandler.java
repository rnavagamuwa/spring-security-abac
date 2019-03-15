package com.rnavagamuwa.springsecurity.abac;

/**
 * @author Randika Navagamuwa
 */
public interface AttributeHandler {

    boolean authorize(String policyRequest);

}
