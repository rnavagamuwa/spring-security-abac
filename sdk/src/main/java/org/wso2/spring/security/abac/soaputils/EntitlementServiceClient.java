package org.wso2.spring.security.abac.soaputils;

import org.springframework.ws.client.core.support.WebServiceGatewaySupport;
import org.wso2.spring.security.abac.soaputils.wsdl.GetEntitledAttributes;
import org.wso2.spring.security.abac.soaputils.wsdl.GetEntitledAttributesResponse;
import org.wso2.spring.security.abac.soaputils.wsdl.ObjectFactory;

/**
 * @author Randika Navagamuwa
 */
public class EntitlementServiceClient extends WebServiceGatewaySupport {

    private String entitlementServiceUrl;

    public EntitlementServiceClient(String entitlementServiceUrl) {

        this.entitlementServiceUrl = entitlementServiceUrl;
    }

    public GetEntitledAttributesResponse getEntitledAttributes(String subjectName, String resourceName,
                                                               String subjectId, String action,
                                                               boolean enableChildSearch) {

        ObjectFactory factory = new ObjectFactory();
        GetEntitledAttributes request = new GetEntitledAttributes();

        request.setSubjectName(factory.createGetEntitledAttributesSubjectName(subjectName));
        request.setResourceName(factory.createGetEntitledAttributesResourceName(resourceName));
        request.setSubjectId(factory.createGetEntitledAttributesSubjectId(subjectId));
        request.setAction(factory.createGetEntitledAttributesAction(action));
        request.setEnableChildSearch(enableChildSearch);

        return (GetEntitledAttributesResponse) getWebServiceTemplate()
                .marshalSendAndReceive(this.entitlementServiceUrl, request);

    }
}
