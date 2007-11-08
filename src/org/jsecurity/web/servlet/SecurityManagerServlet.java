/*
 * Copyright (C) 2005-2007 Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.web.servlet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;

/**
 * Bootstrap servlet to start up the application's {@link org.jsecurity.SecurityManager SecurityManager}
 *
 * <p>This servlet should have a lower <code>load-on-startup</code> value
 * in <code>web.xml</code> than any servlets that access the <tt>SecurityManager</tt>.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class SecurityManagerServlet extends HttpServlet {

    private SecurityManagerLoader securityManagerLoader = new SecurityManagerLoader();

    public void init() throws ServletException {
        securityManagerLoader.setServletContext( getServletContext() );
        securityManagerLoader.ensureSecurityManager();
    }

    public void destroy() {
        this.securityManagerLoader.destroySecurityManager();

    }
}
