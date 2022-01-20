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

import org.apache.commons.io.IOUtils;
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

import java.io.IOException;
import java.io.InputStream;
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

    public static final String CUSTOM_API = "https://localhost:9447/api/identity/auth/v1.1/authenticate";

    public static final String CUSTOM_USER_CLAIM_URI = "https://localhost:9447/scim2/Me";
    public static final String LOCAL_USER_CLAIM_URI = "https://localhost:9443/scim2/Users";

    public static final String ADMIN_USERNAME = "admin";
    public static final String ADMIN_PASSWORD = "admin";

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext oAuthTokenReqMessageContext) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("User Migration Grant handler is hit");
        }

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

                    //call the custom API and retrieve the response.
                    int customApiResCode = 0;

                    try {
                        URL url = new URL(CUSTOM_API);
                        HttpURLConnection apiConnection = (HttpURLConnection) url.openConnection();
                        apiConnection.setRequestMethod("POST");
                        apiConnection.setRequestProperty("Content-Type", "application/json");
                        apiConnection.setRequestProperty("Authorization",
                                "Basic " + Base64.getEncoder().encodeToString(
                                        (usernameParam + ":" + passwordParam).getBytes()
                                )
                        );
                        customApiResCode = apiConnection.getResponseCode();
                    } catch (IOException e) {
                        log.error("The user could not be authenticated due to an IO exception");
                    }

                    //If the user exists, fetch user claims and migrate user profile to IS Server.
                    if (customApiResCode==200) {

                        //fetch user claims
                        String payload = null;

                        try {
                            URL url = new URL(CUSTOM_USER_CLAIM_URI);
                            HttpURLConnection customClaimConnection = (HttpURLConnection) url.openConnection();
                            customClaimConnection.setRequestMethod("GET");
                            customClaimConnection.setRequestProperty("Accept", "application/scim+json; charset=UTF-8");

                            customClaimConnection.setRequestProperty("Authorization",
                                    "Basic " + Base64.getEncoder().encodeToString(
                                            (usernameParam + ":" + passwordParam).getBytes()
                                    )
                            );
                            InputStream in = customClaimConnection.getInputStream();
                            String encoding = customClaimConnection.getContentEncoding();
                            encoding = encoding == null ? "UTF-8" : encoding;
                            payload = IOUtils.toString(in, encoding);

                        } catch (IOException e) {
                            log.error("An IO Exception occurred while fetching user claims");
                        }

                        //migrates fetched user claims to WSO2 Identity Server.
                        try {
                            URL url = new URL(LOCAL_USER_CLAIM_URI);
                            URLConnection urlCon = url.openConnection();
                            HttpURLConnection localClaimConnection = (HttpURLConnection) urlCon;
                            localClaimConnection.setRequestMethod("POST");
                            localClaimConnection.setDoOutput(true);

                            payload = payload.substring(0, payload.length() - 1);
                            payload = payload + String.format(", \"password\":\"%s\"}", passwordParam);

                            byte[] data = payload.getBytes(StandardCharsets.UTF_8);

                            int length = data.length;

                            localClaimConnection.setFixedLengthStreamingMode(length);
                            localClaimConnection.setRequestProperty("Accept", "application/scim+json; charset=UTF-8");
                            localClaimConnection.setRequestProperty("Content-Type", "application/scim+json; charset=UTF-8");
                            localClaimConnection.setRequestProperty("Authorization", "Basic " + Base64.getEncoder().encodeToString((ADMIN_USERNAME + ":" + ADMIN_PASSWORD).getBytes()));

                            localClaimConnection.connect();
                            try (OutputStream stream = urlCon.getOutputStream()) {
                                stream.write(data);
                            }
                            localClaimConnection.disconnect();

                            tenantAwareUserName = MultitenantUtils.getTenantAwareUsername(usernameParam);
                            if(userStoreManager.authenticate(tenantAwareUserName, passwordParam)) {
                                oAuthTokenReqMessageContext.setAuthorizedUser(OAuth2Util.getUserFromUserName(usernameParam));
                                oAuthTokenReqMessageContext.setScope(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getScope());
                                return true;
                            }
                        } catch (Exception e) {
                            log.error("An error occurred while migrating user claims");
                        }

                    } else {
                        log.error("User " + usernameParam + " is not authorized");
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
        responseHeader.setValue("User migration grant was unsuccessful");
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