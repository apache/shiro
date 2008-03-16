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
package org.jsecurity.web.interceptor;

import org.jsecurity.JSecurityException;
import org.jsecurity.web.RedirectView;
import org.jsecurity.web.SecurityWebSupport;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * A WebInterceptor that has the ability to redirect web requests if necessary.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class RedirectingWebInterceptor extends SecurityWebSupport implements WebInterceptor {

    private String url;
    private boolean contextRelative = true;
	private boolean http10Compatible = true;
	private String encodingScheme = RedirectView.DEFAULT_ENCODING_SCHEME;
    private Map queryParams = new HashMap();

    public RedirectingWebInterceptor(){}

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public boolean isContextRelative() {
        return contextRelative;
    }

    public void setContextRelative(boolean contextRelative) {
        this.contextRelative = contextRelative;
    }

    public boolean isHttp10Compatible() {
        return http10Compatible;
    }

    public void setHttp10Compatible(boolean http10Compatible) {
        this.http10Compatible = http10Compatible;
    }

    public String getEncodingScheme() {
        return encodingScheme;
    }

    public void setEncodingScheme(String encodingScheme) {
        this.encodingScheme = encodingScheme;
    }

    public Map getQueryParams() {
        return queryParams;
    }

    public void setQueryParams(Map queryParams) {
        this.queryParams = queryParams;
    }

    /**
     * Default implementation does nothing - can be overridden by subclasses if needed.
     *
     * @throws org.jsecurity.JSecurityException
     */
    public void init() throws JSecurityException {
    }

    protected void issueRedirect(ServletRequest request, ServletResponse response ) throws IOException {
        RedirectView view = new RedirectView( getUrl(), isContextRelative(), isHttp10Compatible() );
        view.renderMergedOutputModel(getQueryParams(), toHttp(request), toHttp(response) );
    }
}
