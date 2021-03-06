package org.wso2.spring.security.abac;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.wso2.spring.security.abac.util.AuthRequestBuilder;
import org.wso2.spring.security.abac.util.XacmlAuthRequestBuilder;

import java.io.Serializable;

/**
 * @author Randika Navagamuwa
 */
public class AttributeEvaluator implements PermissionEvaluator {

    private AuthRequestBuilder authRequestBuilder;
    private AttributeHandler attributeHandler;

    public AttributeEvaluator() {

        this.authRequestBuilder = new XacmlAuthRequestBuilder();
        this.attributeHandler = new XacmlAttributeHandler();
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {

        try {
            return this.attributeHandler.authorize(this.authRequestBuilder.
                    createAuthRequest(targetDomainObject.toString(), permission.toString()));
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {

        return true;
    }

}