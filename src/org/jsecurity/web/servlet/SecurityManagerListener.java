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

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

/**
 * <tt>ServletContextListener</tt> that listens for the ServletContext startup, ensures a
 * {@link org.jsecurity.mgt.SecurityManager SecurityManager} exists, and then binds the <tt>SecurityManager</tt> to the
 * <tt>ServletContext</tt> for later access by the application and framework components (Filters, etc).
 *
 * <p><p>For Servlet 2.2 containers and Servlet 2.3 ones that do not initalize
 * listeners before servlets, use {@link SecurityManagerServlet}.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class SecurityManagerListener extends SecurityManagerLoader implements ServletContextListener {

    public void contextInitialized( ServletContextEvent event ) {
        setServletContext( event.getServletContext() );
        init();
    }

    public void contextDestroyed( ServletContextEvent event ) {
        destroy();
        setServletContext( null );
    }
}
