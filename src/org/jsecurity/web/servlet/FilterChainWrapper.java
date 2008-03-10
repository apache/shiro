/*
 * Copyright (C) 2005-2008 Les Hazlewood
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.*;
import java.io.IOException;
import java.util.List;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class FilterChainWrapper implements FilterChain {

    protected transient final Log log = LogFactory.getLog(getClass());

    private FilterChain orig;
    private List<Filter> filters;
    private int index = 0;

    public FilterChainWrapper( FilterChain orig, List<Filter> filters ) {
        this.orig = orig;
        this.filters = filters;
        this.index = 0;
    }

    public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
        if ( this.filters == null || this.filters.size() == this.index ) {
            //we've reached the end of the wrapped chain, so invoke the original one:
            if ( log.isTraceEnabled() ) {
                log.trace( "Invoking original filter chain." );
            }
            this.orig.doFilter( request, response );
        } else {
            if ( log.isTraceEnabled() ) {
                log.trace( "Invoking wrapped filter at index [" + this.index + "]" );
            }
            this.filters.get(this.index++).doFilter(request,response,this);
        }
    }
}
