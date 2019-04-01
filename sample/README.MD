# XACML based authorization for Spring security - Sample

### Overview

Even though spring security provides role-based access control it doesn’t allow users to perform policy-based authorization. The main goal of this project is to write an agent which can be used to perform attribute-based access control for Spring security. 

### Implementation

Spring security provides an annotation for custom authorization evaluations.

As the initial version, I have managed to write a working sample for this use case. This sample talks to WSO2 PDP for authorization.

#### Usage

1. Start WSO2-IS by following [Installation Guide](https://docs.wso2.com/display/IS570/Installation+Guide).
2. Publish the following XAML Policy by following [Publishing a XACML Policy](https://docs.wso2.com/display/IS570/Publishing+a+XACML+Policy).
    ```
    <Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="samplePolicy" RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides" Version="1.0">
        <Target>
            <AnyOf>
                <AllOf>
                    <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                        <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">read</AttributeValue>
                        <AttributeDesignator AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id" Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action" DataType="http://www.w3.org/2001/XMLSchema#string" MustBePresent="true"></AttributeDesignator>
                    </Match>
                </AllOf>
            </AnyOf>
        </Target>
        <Rule Effect="Permit" RuleId="permit"></Rule>
    </Policy>
    ```
3. Configure SSO by following [Configure Single Sign-On](https://docs.wso2.com/display/IS570/Configuring+Single+Sign-On)
   - Issuer id : com:rnavagamuwa:springsecurity
   - Assertion consumer URL : http://localhost:8080/saml/SSO
   - SLO response\request URL : http://localhost:8080/saml/SingleLogout
4. Replace the `keystore,jks` and a `trustStore,jks` in *Resources* directory with the correct ones.
      
5. Define following properties in the `application.properties` file.
   ```
   xacml.pdp.url.entitlement.service=https://localhost:9443/api/identity/entitlement/decision   xacml.pdp.url.resourceList=https://localhost:9443/api/identity/entitlement/decision/home
   xacml.pdp.trustStore=truststore.jks
   xacml.pdp.trustStore.password=password
   xacml.pdp.keyStore=keystore.jks
   xacml.pdp.keyStore.password=password
   ```          
6. Run the spring boot app by executing `mvn spring-boot:run`
7. Navigate to [http://localhost:8080](http://localhost:8080) and you'll be redirected to the following page.
   ![](https://i.imgur.com/oPHkonjl.png)
8. Provide the username and password. (Default is `admin`,`admin`). Then you'll be redirected to the landing page.
   ![](https://i.imgur.com/OryiqQ1.png)
9. Then click on `Hello` button. Add the following authorization headers and click on `Submit Request`
   - Header Key : **action-id** | Header Value : **read**
   - Header Key : **resource-id** | Header Value : **http://127.0.0.1/service/very_secure/**
   
   You should get the message `Successfully authorized` message if authorized.
   
   ![](https://i.imgur.com/wzfOT6p.png)
   
10. In addition to this you can remove the headers and submit.