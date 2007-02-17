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

package org.jsecurity.spring;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.util.Destroyable;
import org.jsecurity.util.Initializable;
import org.springframework.beans.BeansException;
import org.springframework.beans.FatalBeanException;
import org.springframework.beans.factory.config.DestructionAwareBeanPostProcessor;

/**
 * <p>Bean post processor for Spring that automatically calls the <tt>init()</tt> and/or
 * <tt>destroy()</tt> methods on JSecurity objects that implement the {@link org.jsecurity.util.Initializable}
 * or {@link org.jsecurity.util.Destroyable} interfaces, respectfully.  This post processor makes it easier
 * to configure JSecurity beans in Spring, since the user never has to worry about whether or not
 * an object requires the init/destroy methods to be called.</p>
 *
 * <p><b>Warning: This post processor has no way to determine if <tt>init()</tt> or <tt>destroy()</tt> have
 * already been called, so if you configure this post processor, do not also call these methods manually
 * or via Spring's <tt>init-method</tt> or <tt>destroy-method</tt> bean attributes.</b></p>
 *
 * @since 0.2
 * @author Jeremy Haile
 */
public class SecurityBeanPostProcessor implements DestructionAwareBeanPostProcessor {

    /**
     * Commons-logging logger
     */
    protected final transient Log logger = LogFactory.getLog(getClass());

    /**
     * Calls the <tt>init()</tt> methods on the bean if it implements {@link org.jsecurity.util.Initializable}
     * @param object the object being initialized.
     * @param name the name of the bean being initialized.
     * @return the initialized bean.
     * @throws BeansException if any exception is thrown during initialization.
     */
    public Object postProcessBeforeInitialization(Object object, String name) throws BeansException {
        if( object instanceof Initializable) {
            try {
                if (logger.isDebugEnabled()) {
                    logger.debug("Initializing bean [" + name + "]...");
                }

                ((Initializable)object).init();
            } catch (Exception e) {
                throw new FatalBeanException( "Error initializing bean [" + name + "]", e);
            }
        }
        return object;
    }


    public Object postProcessAfterInitialization(Object object, String name) throws BeansException {
        // Does nothing after initialization
        return object;
    }


    /**
     * Calls the <tt>destroy()</tt> methods on the bean if it implements {@link org.jsecurity.util.Destroyable}
     * @param object the object being initialized.
     * @param name the name of the bean being initialized.
     * @throws BeansException if any exception is thrown during initialization.
     */
    public void postProcessBeforeDestruction(Object object, String name) throws BeansException {
         if( object instanceof Destroyable) {
            try {
                if (logger.isDebugEnabled()) {
                    logger.debug("Destroying bean [" + name + "]...");
                }

                ((Destroyable)object).destroy();
            } catch (Exception e) {
                throw new FatalBeanException( "Error destroying bean [" + name + "]", e);
            }
        }
    }
}