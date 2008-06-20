/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.web.filter.authz;

import org.jsecurity.subject.Subject;
import static org.jsecurity.util.StringUtils.split;
import org.jsecurity.web.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class RolesAuthorizationFilter extends AuthorizationFilter {

    public void processPathConfig(String path, String config) {
        if (config != null) {
            String[] values = split(config);
            if (values != null) {
                Set<String> set = new LinkedHashSet<String>(Arrays.asList(values));
                this.appliedPaths.put(path, set);
            }
        }
    }

    @SuppressWarnings({"unchecked"})
    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {

        Subject subject = WebUtils.getSubject(request, response);
        Set<String> roles = (Set<String>) mappedValue;

        if (roles != null && !roles.isEmpty()) {
            if (roles.size() == 1) {
                if (!subject.hasRole(roles.iterator().next())) {
                    issueRedirect(request, response);
                }
            } else {
                if (!subject.hasAllRoles(roles)) {
                    issueRedirect(request, response);
                }
            }
        }

        return true;
    }
}
