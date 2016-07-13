/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.web.faces.tags;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.StringUtils;

import javax.faces.view.facelets.TagConfig;

/**
 * Tag that renders the tag body only if the current user has <em>at least one</em> of the comma-delimited
 * string permissions specified in <tt>name</tt> attribute.
 *
 * @since 2.0
 */
public class HasAnyPermissionsTag extends AuthorizationTagHandler {

    public HasAnyPermissionsTag(TagConfig config) {
        super(config);
    }

    @Override
    protected boolean showTagBody(String commaDelimitedPermissions) {
        boolean hasAnyPermission = false;

        Subject subject = getSubject();

        if (subject != null) {
            // Iterate through permissions and check to see if the user has one of the permission
            String[] permissions = StringUtils.split(commaDelimitedPermissions);
            for (String permission : permissions) {
                if (subject.isPermitted(permission)) {
                    hasAnyPermission = true;
                    break;
                }
            }
        }

        return hasAnyPermission;
    }
}
