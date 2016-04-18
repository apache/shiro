/*
 * Copyright 2016 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shiro.util;

import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.util.tracker.ServiceTracker;

/**
 *
 * @author mnn
 * @param <T>
 */
public class OSGiAdapter<T extends Object> implements Adapter<T>{
    ServiceTracker<T, T> tracker;

    public OSGiAdapter(BundleContext context, ServiceReference<T> ref) {
	tracker = new ServiceTracker<T, T>(context, ref, null);
    }
    
    

    public T getInstance() {
	return tracker.getService();
    }

    public void setInstance(T toSet) throws IllegalStateException {
	throw new IllegalStateException("Cannot set instance on this adapter");
    }
    
    
    
    
}
