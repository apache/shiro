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
package org.apache.shiro.ee.filters;

import static org.apache.shiro.ee.filters.FormResubmitSupport.hasFacesContext;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import lombok.Getter;
import lombok.Setter;
import org.omnifaces.util.Faces;

/**
 * Enables Shiro's SslFilter depending
 * depending on whether in Faces production mode or not
 */
public class SslFilter extends org.apache.shiro.web.filter.authz.SslFilter {
    @Getter @Setter
    private boolean enablePortFilter = true;
    @Getter @Setter
    private boolean alwaysEnabled = false;
    private final boolean enabled = computeEnabled();

    @Override
    protected boolean isEnabled(ServletRequest request, ServletResponse response) throws ServletException, IOException {
        return alwaysEnabled || enabled && super.isEnabled(request, response);
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        if (!enablePortFilter) {
            mappedValue = new String[] { Integer.toString(request.getServerPort()) };
        }
        return super.isAccessAllowed(request, response, mappedValue);
    }

    private boolean computeEnabled() {
        if (hasFacesContext()) {
            return !Faces.isDevelopment();
        } else {
            return true;
        }
    }
}
