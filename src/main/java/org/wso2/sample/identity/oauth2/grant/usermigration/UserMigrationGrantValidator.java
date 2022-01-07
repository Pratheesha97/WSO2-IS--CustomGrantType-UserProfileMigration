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

import org.apache.oltu.oauth2.common.validators.AbstractValidator;
import javax.servlet.http.HttpServletRequest;

/**
 * This validates the user migration grant request.
 */
public class UserMigrationGrantValidator extends AbstractValidator<HttpServletRequest> {

    public UserMigrationGrantValidator() {

        // username and password must be in the request parameter
        requiredParams.add(UserMigrationGrant.USERNAME_PARAM_MIGRATION_GRANT);
        requiredParams.add(UserMigrationGrant.PASSWORD_PARAM_MIGRATION_GRANT);
    }

}
