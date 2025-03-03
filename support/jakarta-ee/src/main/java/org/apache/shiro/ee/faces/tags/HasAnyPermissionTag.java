/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.ee.faces.tags;

import org.apache.shiro.subject.Subject;

import jakarta.faces.view.facelets.TagConfig;

/**
 * Tag that renders the tag body only if the current user has <em>at least one</em> of the comma-delimited
 * string permissions specified in name attribute.
 */
public class HasAnyPermissionTag extends PermissionTagHandler {
    private static final String PERMISSIONS_DELIMETER = ",";

    public HasAnyPermissionTag(TagConfig config) {
        super(config);
    }

    @Override
    protected boolean showTagBody(String permissions) {
        boolean hasAnyPermission = false;

        Subject subject = getSubject();

        if (subject != null) {
            // Iterate through permissions and check to see if the user has one of the permission
            for (String permission : permissions.split(PERMISSIONS_DELIMETER)) {
                if (subject.isPermitted(permission.trim())) {
                    hasAnyPermission = true;
                    break;
                }
            }
        }

        return hasAnyPermission;
    }
}
