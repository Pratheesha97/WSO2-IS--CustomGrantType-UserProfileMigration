# User Migration Grant

## Recommended use 

The user migration grant type is appropriate in cases where a user doesn’t exist in the WSO2 Identity Server and needs to be migrated to the WSO2 Identity Server from an external userstore in the event of sign-in. In other words, when a runtime user migration needs to be performed. 

This custom grant type is designed by extending the [password grant type](https://is.docs.wso2.com/en/latest/learn/resource-owner-password-credentials-grant/). Therefore, this is most suitable when the resource owner has a trust relationship with the client and in cases where the client can obtain the resource owner’s credentials (e.g., a service’s own mobile client). 

## The flow

Instead of redirecting the user to the authorization server, the client itself will prompt the user for the resource owner's username and password. Then, the client will send these user credentials to the authorization server along with the client’s own credentials. The authorization server will check if the user exists locally in the local userstore. If not, the  authorization server will attempt to authenticate the user through a custom api. If succeeds, the user claims stored in the external userstore will be migrated to the local userstore of the authorization server and an access token will be issued. 

The diagram below illustrates the user migration grant flow.

**Case 1: The user exists in the WSO2 Identity Server.**

<img src="https://user-images.githubusercontent.com/55917205/150393345-828307c1-b175-44dd-85f8-4d1719a52217.png" width="730" height="500">

**Case 2: The user doesn’t exist in the WSO2 Identity Server but exists in the external authorization server.**

![image](https://user-images.githubusercontent.com/55917205/150318207-0b25ad67-b2b4-4ce6-bf3c-51a491884a57.png)

The cURL command below can be used to try this grant type.

```sh
curl -u <client id>:<client secret> -k -d "grant_type=migration&username=<username>&password=<password>" -H "Content-Type:application/x-www-form-urlencoded" https://localhost:9443/oauth2/token
  ```
You will receive a response similar to the format below.

**Response**
```sh
{"access_token":"89c1de95-ae66-302c-92ea-9b7f5cc0acb5","refresh_token":"49a2914f-dade-3429-8fd1-2d394dc03a90","token_type":"Bearer","expires_in":3326}
 ```
 
## Try User Migration Grant
 
1. Clone the repository and then open the project using IntelliJ IDEA or any other IDE.

2. Using the command line, navigate to the project root directory, and run the following Apache Maven command.

                       mvn clean install        
3. You should be able to see a JAR file named “user-migration-grant-`<version>`.jar” in the `<project_home>`/target directory.

4. Copy the JAR file into the `<IS_HOME>`/repository/component/lib directory.

5. In order to register the custom grant type, configure the `<IS_HOME>`/repository/conf/deployment.toml file by adding a new entry, in a manner similar to the following example.
                        
                  [[oauth.custom_grant_type]]
                  name="migration"
                  grant_handler="org.wso2.sample.identity.oauth2.grant.usermigration.UserMigrationGrant"
                  grant_validator="org.wso2.sample.identity.oauth2.grant.usermigration.UserMigrationGrantValidator"
                  [oauth.custom_grant_type.properties]
                  IdTokenAllowed=true
    ###### Setting the `<IdTokenAllowed>` parameter to true, provides flexibility to control the issuing of ID token for each grant, and also allows the OIDC scope validator to validate the grant types that should support the openid scope. ######

6. Restart the server.

7. Configure the new Oauth grant type.

   a. Sign in to the WSO2 Identity Server. Enter your username and password to log on to the Management Console.

   b. Navigate to the **Main** menu to access the **Identity** menu. Click **Add** under **Service Providers**.

   c. Fill in the **Service Provider Name** and provide a brief **Description** of the service provider. 	
  
   d. Expand the **OAuth/OpenID Connect Configuration** and click **Configure**.

   e. Check that the `migration` grant type is selected as shown below.
  
   <img src="https://user-images.githubusercontent.com/55917205/150388817-eb6ae640-5d93-4c68-b9e8-d20259c1c4b8.png" width="600" height="350">
  
   f. Enter a callback URL. For example, http://localhost.com:8080/pickup-dispatch/oauth2client.
  
   g. Click **Add**.
  
   h. The **OAuth Client Key** and **OAuth Client Secret** will now be visible.
  
8. Send the grant request to the /token API using a cURL command.
  
   a. The HTTP POST body must contain the following three parameters: grant_type=migration, username and password.
      ```sh
      grant_type=migration&username=<username>&password=<password>
      ```
  
   b. Replace `<username>` and `<password>` with username and password of the user and `clientid:clientsecret` with the OAuth Client Key and OAuth Client Secret    respectively, and run the following sample cURL command in a new terminal window.
  
      ```sh
      curl -u clientid:clientsecret -k -d "grant_type=migration&username=<username>&password=<password>" -H "Content-Type: application/x-www-form-urlencoded" https://localhost:9443/oauth2/token
      ```
  
   c. The user will be migrated to the local userstore of the Identity Server and you will receive the following JSON response with the access token.
      ```sh
      {"access_token":"89c1de95-ae66-302c-92ea-9b7f5cc0acb5","refresh_token":"49a2914f-dade-3429-8fd1-2d394dc03a90","token_type":"Bearer","expires_in":3326}
      ```
  

