/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.sample.identity.oauth2.grant.usermigration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.PasswordGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * New grant type for Identity Server that performs Runtime User Migration
 */
public class UserMigrationGrant extends PasswordGrantHandler {

    private static Log log = LogFactory.getLog(UserMigrationGrant.class);

    public static final String USERNAME_PARAM_MIGRATION_GRANT = "username";
    public static final String PASSWORD_PARAM_MIGRATION_GRANT = "password";

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext oAuthTokenReqMessageContext) throws IdentityOAuth2Exception {

        log.info("User Migration Grant handler is hit");

        String usernameParam = null;
        String passwordParam = null;

        // extract request parameters
        RequestParameter[] parameters = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getRequestParameters();

        for (RequestParameter parameter : parameters) {
            if (USERNAME_PARAM_MIGRATION_GRANT.equals(parameter.getKey())) {
                if (parameter.getValue() != null && parameter.getValue().length > 0) {
                    usernameParam = parameter.getValue()[0];
                }
            }
            if (PASSWORD_PARAM_MIGRATION_GRANT.equals(parameter.getKey())) {
                if (parameter.getValue() != null && parameter.getValue().length > 0) {
                    passwordParam = parameter.getValue()[0];
                }
            }
        }

        if (usernameParam != null && passwordParam != null) {

            try {
                UserStoreManager userStoreManager = (UserStoreManager)
                        CarbonContext.getThreadLocalCarbonContext().getUserRealm().getUserStoreManager();

                String tenantAwareUserName = MultitenantUtils.getTenantAwareUsername(usernameParam);

                boolean authorized = userStoreManager.authenticate(tenantAwareUserName, passwordParam);

                //checks if the user can be authenticated locally. if not, migrates the user.
                if (authorized) {
                    oAuthTokenReqMessageContext.setAuthorizedUser(OAuth2Util.getUserFromUserName(usernameParam));
                    oAuthTokenReqMessageContext.setScope(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getScope());
                    return true;
                } else {
                    //Call the custom API and retrieve the response (to be completed).

                    if (true) {

                        //If the user exists, migrate user attributes and claims to WSO2 Identity Server.
                        String apiUrl = "https://localhost:9443/scim2/Users";
                        String adminUsername = "admin";
                        String adminPassword = "admin";

                        try {
                            URL url = new URL(apiUrl);
                            URLConnection urlCon = url.openConnection();
                            HttpURLConnection connection = (HttpURLConnection) urlCon;
                            connection.setRequestMethod("POST");
                            connection.setDoOutput(true);

                            byte[] data = "{ \"schemas\": [], \"name\": { \"givenName\": \"Kim\", \"familyName\": \"Berry\" }, \"userName\": \"kim\", \"password\": \"abc123\", \"emails\": [ { \"type\": \"home\", \"value\": \"kim@gmail.com\", \"primary\": true }, { \"type\": \"work\", \"value\": \"kim@wso2.com\" } ], \"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User\": { \"employeeNumber\": \"1234A\", \"manager\": { \"value\": \"Taylor\" } }}".getBytes(StandardCharsets.UTF_8);
                            int length = data.length;

                            connection.setFixedLengthStreamingMode(length);
                            connection.setRequestProperty("Accept", "application/scim+json; charset=UTF-8");
                            connection.setRequestProperty("Content-Type", "application/scim+json; charset=UTF-8");
                            connection.setRequestProperty("Authorization", "Basic " + Base64.getEncoder().encodeToString((adminUsername + ":" + adminPassword).getBytes()));

                            connection.connect();
                            try (OutputStream stream = urlCon.getOutputStream()) {
                                stream.write(data);
                            }
                            System.out.println(connection.getResponseCode() + " " + connection.getResponseMessage());
                            connection.disconnect();
                        } catch (Exception e) {
                            log.error("An error occurred when migrating user attributes and claims");
                        }

                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("User " + usernameParam + " is not authorized");
                        }
                    }

                }
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                log.error(e);
            }
        } else {
            log.error("username " + usernameParam + " and password " + passwordParam + " required parameters missing");
        }
        ResponseHeader responseHeader = new ResponseHeader();
        responseHeader.setKey("HTTP_STATUS_CODE");
        responseHeader.setValue("402");
        responseHeader.setKey("ERROR_MESSAGE");
        responseHeader.setValue("Mobile grant was unsuccessful");
        oAuthTokenReqMessageContext.addProperty("RESPONSE_HEADERS", new ResponseHeader[]{responseHeader});
        return false;
    }

    @Override
    public boolean authorizeAccessDelegation(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {
        return true;
    }

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext toReqMsgCtx) throws IdentityOAuth2Exception {
        return true;
    }

}
