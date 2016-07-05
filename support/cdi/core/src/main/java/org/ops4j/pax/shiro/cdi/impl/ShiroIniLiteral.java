/*
 * Copyright 2013 Harald Wellmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.ops4j.pax.shiro.cdi.impl;

import javax.enterprise.util.AnnotationLiteral;

import org.ops4j.pax.shiro.cdi.ShiroIni;


/**
 * A literal for the {@link ShiroIni} annotation.
 * 
 * @author Harald Wellmann
 *
 */
public class ShiroIniLiteral extends AnnotationLiteral<ShiroIni> {
   
    /** Annotation literal instance. */
    public static final ShiroIniLiteral INSTANCE = new ShiroIniLiteral();
    
    private static final long serialVersionUID = 1L;

}
