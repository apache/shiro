/*
 * Copyright 2005-2008 Jeremy Haile
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
package org.jsecurity.web.tags;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.TagSupport;

/**
 * JSP tag that renders the tag body only if the current user has <em>not</em> executed a successful authentication
 * attempt <em>during their current session</em>.
 *
 * <p>The logically opposite tag of this one is the {@link AuthenticatedTag}.
 *
 * @since 0.2
 * @author Jeremy Haile
 */
public class NotAuthenticatedTag extends SecureTag {

    public int onDoStartTag() throws JspException {
        if ( getSubject() == null || !getSubject().isAuthenticated() ) {
            if ( log.isTraceEnabled() ) {
                log.trace( "Subject does not exist or is not authenticated.  Tag body will be evaluated." );
            }
            return TagSupport.EVAL_BODY_INCLUDE;
        } else {
            if ( log.isTraceEnabled() ) {
                log.trace( "Subject exists and is authenticated.  Tag body will not be evaluated." );
            }
            return TagSupport.SKIP_BODY;
        }
    }
}