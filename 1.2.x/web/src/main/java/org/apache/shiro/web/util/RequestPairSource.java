/*
 * Copyright 2008 Les Hazlewood
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
package org.apache.shiro.web.util;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * A {@code RequestPairSource} is a component that can supply a {@link ServletRequest ServletRequest} and
 * {@link ServletResponse ServletResponse} pair associated with a currently executing request.  This is used for
 * framework development support and is rarely used by end-users.
 *
 * @since 1.0
 */
public interface RequestPairSource {

    /**
     * Returns the incoming {@link ServletRequest ServletRequest} associated with the component.
     *
     * @return the incoming {@link ServletRequest ServletRequest} associated with the component.
     */
    ServletRequest getServletRequest();

    /**
     * Returns the outgoing {@link ServletResponse ServletResponse} paired with the incoming
     * {@link #getServletRequest() servletRequest}.
     *
     * @return the outgoing {@link ServletResponse ServletResponse} paired with the incoming
     *         {@link #getServletRequest() servletRequest}.
     */
    ServletResponse getServletResponse();
}
