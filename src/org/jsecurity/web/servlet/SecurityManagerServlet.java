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
package org.jsecurity.web.servlet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;

/**
 * Bootstrap servlet to start up the application's {@link org.jsecurity.mgt.SecurityManager SecurityManager}
 *
 * <p>This servlet should have a lower <code>load-on-startup</code> value
 * in <code>web.xml</code> than any servlets that access the <tt>SecurityManager</tt>.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class SecurityManagerServlet extends HttpServlet {

    protected SecurityManagerLoader securityManagerLoader = null;

    protected SecurityManagerLoader newLoaderInstance() {
        return new SecurityManagerLoader();
    }

    public void init() throws ServletException {
        SecurityManagerLoader loader = newLoaderInstance();
        loader.setServletContext( getServletContext() );
        loader.init();
        this.securityManagerLoader = loader;
    }

    public void destroy() {
        this.securityManagerLoader.destroy();

    }
}
