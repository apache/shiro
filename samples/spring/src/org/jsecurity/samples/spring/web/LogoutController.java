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
package org.jsecurity.samples.spring.web;

import org.jsecurity.SecurityUtils;
import org.jsecurity.subject.Subject;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.AbstractController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Controller responsible for logging out the current user by invoking
 * {@link org.jsecurity.subject.Subject#logout()}
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class LogoutController extends AbstractController {

    protected ModelAndView handleRequestInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Exception {
        Subject subject = SecurityUtils.getSubject();
        if ( subject != null ) {
            subject.logout();
        }
        return new ModelAndView( "redirect:login" );
    }
}