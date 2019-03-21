package org.wso2.spring.security.abac;

import org.json.JSONObject;

import java.util.Optional;

/**
 * @author Randika Navagamuwa
 */
public interface AttributeHandler {

    boolean authorize(String policyRequest);

    Optional<JSONObject> getApiResourceList();
}
