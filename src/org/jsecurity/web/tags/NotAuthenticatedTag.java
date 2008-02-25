/*
 * Copyright (C) 2005-2007 Jeremy Haile
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
package org.jsecurity.web.tags;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.TagSupport;

/**
 * JSP tag that renders the tag body if the current user is not authenticated.  If the
 * user is authenticated, the tag body is skipped.
 *
 * @since 0.2
 * @author Jeremy Haile
 */
public class NotAuthenticatedTag extends SecureTag {

    public int onDoStartTag() throws JspException {
        if ( getSubject() == null || !getSubject().isAuthenticated() ) {
            if ( log.isTraceEnabled() ) {
                log.trace( "Subject does not exist or is not authenticated.  'notAuthenticated' tag body " +
                    "will be evaluated." );
            }
            return TagSupport.EVAL_BODY_INCLUDE;
        } else {
            if ( log.isTraceEnabled() ) {
                log.trace( "Subject exists and is authenticated.  'notAuthenticated' tag body " +
                    "will not be evaluated." );
            }
            return TagSupport.SKIP_BODY;
        }
    }
}