# XACML based authorization for Spring security - SDK

### Overview

Even though spring security provides role-based access control it doesn’t allow users to perform policy-based authorization. The main goal of this project is to write an agent which can be used to perform attribute-based access control for Spring security. 

### Implementation

Spring security provides an annotation for custom authorization evaluations.

As the initial version, I have managed to write a working sample for this use case. This sample talks to WSO2 PDP for authorization.

#### The high-level sequence diagram


![](https://i.imgur.com/CUBbSxB.png)


#### Usage

1. Create a `keystore` and a `trustStore` in *Resources* directory.
2. Create a file named `xacmlConfig.json` in *Resources* directory. This file contains the body of the XACML request.
     * This file is a json file and this can have more than one *Target Domain Objects*. In this case let's define our target domain object as **admin_xacml**.
     * All the variables should be passed as **'${variable}'**. For example if **action-id** is the variable it should be defined in the `xacmlConfig.sjon` as **${actionid}**.
            
     A sample `xacmlConfig.json` file is as follows.
     ````
     {
       "admin_xacml": {
         "Request": {
           "Action": {
             "Attribute": [
               {
                 "AttributeId": "urn:oasis:names:tc:xacml:1.0:action:action-id",
                 "Value": "${actionid}"
               }
             ]
           },
           "Resource": {
             "Attribute": [
               {
                 "AttributeId": "urn:oasis:names:tc:xacml:1.0:resource:resource-id",
                 "Value": "${resourceid}"
               }
             ]
           }
         }
       }
     }
     ````
      
3. Define following properties in the `application.properties` file.
   ```
   xacml.pdp.url.entitlement.service=https://localhost:9443/api/identity/entitlement/decision
   xacml.pdp.trustStore=truststore
   xacml.pdp.trustStore.password=password
   xacml.pdp.keyStore=keystore
   xacml.pdp.keyStore.password=password
   ```          
4. Extend `GlobalMethodSecurityConfiguration` class and set `AttributeEvaluator` as the new `PermissionEvaluator`
    ```
    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {
    
        @Override
        protected MethodSecurityExpressionHandler createExpressionHandler() {
    
            DefaultMethodSecurityExpressionHandler expressionHandler =
                    new DefaultMethodSecurityExpressionHandler();
            expressionHandler.setPermissionEvaluator(new AttributeEvaluator());
            return expressionHandler;
        }
    }
    ```
5. Now add the `@PreAuthorize("hasPermission()")` or `@PostAuthorize("hasPermission()")` annotation as required before the correct controller method. 
*Target Domain Object* and the *Permissions* should be passed to this annotation as parameters.*Permissions* is a json object which contains the key value pairs. 
Permission values can be extracted from any of the following.
     - Headers
        - Pass the value as `header.value`
     - Query params
        - Pass the value as `queryParam.value`
     - Path params
        - Pass the value as `pathParam.value`
     - Form data
        - Pass the value as `formData.value`
     - Cookies 
        - Pass the value as `cookie.value`
 
    For example, let's assume we want to extract `action-id` and `resource-id` from headers.       
   ```
    @PreAuthorize("hasPermission('admin_xacml','{$action-id:action-id,$resource-id:resource-id}')")
    ```

#### Other exposed APIs
In addition to XACML Based Authorization, this SDK exposes following methods 

   - API Resources List
     - `getApiResourceList()` can be used to get the API Resource List. Response is a XACML JSON Object.
   - Get entitled attributes
     - `getEntitledAttributes(String subjectName, String resourceName, String subjectId, String action, boolean enableChildSearch)` method
     should be called and the response will be a JSON object with the following format
     ```
     EntitledAttributesResponseModel {
     	entitledResultSetDTO:EntitledResultSetDTO {
     		entitledAttributesDTOs:[
     			EntitledAttributesDTO {
     				resourceName:string
     				action:string
     				environment:string
     				allActions:boolean
     				allResources:boolean
     				attributeDTOs:[
     					AttributeDTO {
     						attributeValue:string
     						attributeDataType:string
     						attributeId:string
     						category:string
     					}
     				]
     			}
     		]
     		advanceResult:boolean
     		message:string
     		messageType:string
     	}
     }
     ```