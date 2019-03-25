package org.wso2.spring.security.abac;

import org.json.JSONObject;
import org.wso2.spring.security.abac.soaputils.wsdl.EntitledResultSetDTO;

import java.util.Optional;
import javax.xml.bind.JAXBElement;

/**
 * @author Randika Navagamuwa
 */
public interface AttributeHandler {

    boolean authorize(String policyRequest);

    Optional<JSONObject> getApiResourceList();

    JAXBElement<EntitledResultSetDTO> getEntitledAttributes(String subjectName, String resourceName, String subjectId, String action,
                                                            boolean enableChildSearch);
}
