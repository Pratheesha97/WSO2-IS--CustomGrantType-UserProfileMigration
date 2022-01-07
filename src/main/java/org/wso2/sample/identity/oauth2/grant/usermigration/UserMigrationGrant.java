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
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.PasswordGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

/**
 * New grant type for Identity Server that performs Runtime User Migration
 */
public class UserMigrationGrant extends PasswordGrantHandler {

    private static Log log = LogFactory.getLog(UserMigrationGrant.class);

    public static final String USERNAME_PARAM_MIGRATION_GRANT = "username";
    public static final String PASSWORD_PARAM_MIGRATION_GRANT = "password";

    public static final String DEFAULT_PROFILE = "default";

    private static final String USERNAME_CLAIM_URI = "http://wso2.org/claims/username";


    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext oAuthTokenReqMessageContext) throws IdentityOAuth2Exception {

        log.info("User Migration Grant handler is hit");

        String username = null;
        String usernameParam = null;
        String passwordParam = null;

        // extract request parameters
        RequestParameter[] parameters = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getRequestParameters();

        // fetch username and password
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
            OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO();
            String tenantDomain = oAuth2AccessTokenReqDTO.getTenantDomain();

            try {
                UserStoreManager userStoreManager = (UserStoreManager)
                        CarbonContext.getThreadLocalCarbonContext().getUserRealm().getUserStoreManager();

                String[] userList = userStoreManager.getUserList(USERNAME_CLAIM_URI, usernameParam,
                        DEFAULT_PROFILE);

                if (userList == null || userList.length == 0) {
                    String errorMessage = "No user found with the provided " + USERNAME_CLAIM_URI + ": " + usernameParam;
                    if (log.isDebugEnabled()) {
                        log.debug(errorMessage);
                    }
                } else if (userList.length == 1) {
                    username = userList[0];
                    String tenantAwareUserName = MultitenantUtils.getTenantAwareUsername(username);
                    username = tenantAwareUserName + "@" + tenantDomain;
                    if (log.isDebugEnabled()) {
                        log.debug("Found single user: " + username + " with the provided username: " + usernameParam);
                    }

                    boolean authorized = userStoreManager.authenticate(tenantAwareUserName, passwordParam);
                    if (authorized) {
                        oAuthTokenReqMessageContext.setAuthorizedUser(OAuth2Util.getUserFromUserName(username));
                        oAuthTokenReqMessageContext.setScope(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getScope());
                        return true;
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("User " + username + " is not authorized");
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("User not found with the provided username: " + usernameParam);
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
