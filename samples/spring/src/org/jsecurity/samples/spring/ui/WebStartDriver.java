/*
 * Copyright (C) 2007 Jeremy Haile
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
package org.jsecurity.samples.spring.ui;

import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * Driver class used to launch the web start application by loading a
 * Spring application context.  Once the Spring application context is
 * loaded, the initialization of the {@link WebStartView} does the rest.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class WebStartDriver {

    public static void main(String[] args) {
        new ClassPathXmlApplicationContext( "webstart.spring.xml" );
    }
}
