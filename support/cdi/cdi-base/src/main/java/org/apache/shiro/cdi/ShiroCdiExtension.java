/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.cdi;

import org.apache.shiro.cdi.EventListenerRegistrationInterceptor.ProcessShiroEventBusConsumer;
import org.apache.shiro.cdi.ShiroAnnotationInterceptor.ProcessShiroAnnotations;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.event.EventBusAware;
import org.apache.shiro.event.Subscribe;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.AfterDeploymentValidation;
import javax.enterprise.inject.spi.AnnotatedConstructor;
import javax.enterprise.inject.spi.AnnotatedField;
import javax.enterprise.inject.spi.AnnotatedMethod;
import javax.enterprise.inject.spi.AnnotatedType;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.Extension;
import javax.enterprise.inject.spi.ProcessAnnotatedType;
import javax.enterprise.inject.spi.ProcessBean;
import javax.enterprise.inject.spi.WithAnnotations;
import javax.enterprise.util.AnnotationLiteral;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ShiroCdiExtension implements Extension {

    private List<Bean<?>> eagerBeansList = new ArrayList<Bean<?>>();

    // Registering instances with Shiro's EventBus is a 4 part process:
    // 1. registerEventListeners()/registerEventBusAware() detects any AnnotatedType with an 'Subscribe' annotation
    //    and adds an additional annotation 'ProcessShiroEventBusConsumer' to mark the bean for interception
    // 2. collectEventListeners() finds the Beans that were Annotated with 'ProcessShiroEventBusConsumer' and adds
    //    them to the 'eagerBeansList'
    // 3. eagerLoadBeans() initializes these beans
    // 4. EventListenerRegistrationInterceptor adds a 'PostConstruct' interceptor that registers the instance with the
    //    EventBus instance or calls setEventBus()

    private <X> void registerEventBusAware(@Observes ProcessAnnotatedType<X> pat) {

        if(EventBusAware.class.isAssignableFrom(pat.getAnnotatedType().getJavaClass())) {
            addProcessShiroEventConsumerAnnotation(pat);
        }
    }

    private <X> void registerEventListeners(@Observes @WithAnnotations({Subscribe.class}) ProcessAnnotatedType<X> pat) {
        addProcessShiroEventConsumerAnnotation(pat);
    }

    private <X> void addProcessShiroEventConsumerAnnotation(ProcessAnnotatedType<X> pat) {

        // wrap this to override the annotations of the class
        final AnnotatedType<X> at = pat.getAnnotatedType();

        pat.setAnnotatedType(new AdditionalAnntoationType<X, ProcessShiroEventBusConsumer>(at, ProcessShiroEventBusConsumer.class) {
            @Override
            public Set<Annotation> getAnnotations() {
                Set<Annotation> original = at.getAnnotations();
                Set<Annotation> annotations = new HashSet<>(original);
                annotations.add(new AnnotationLiteral<ProcessShiroEventBusConsumer>() {});
                return annotations;
            }
        });
    }

    private <T> void collectEventListeners(@Observes ProcessBean<T> event) {
        if(event.getAnnotated().isAnnotationPresent(ApplicationScoped.class)) {
            if(event.getAnnotated().isAnnotationPresent(ProcessShiroEventBusConsumer.class)
                    || EventBusAware.class.isAssignableFrom(event.getBean().getBeanClass()) ) {
                eagerBeansList.add(event.getBean());
            }
        }
    }

    private void eagerLoadBeans(@Observes AfterDeploymentValidation event, BeanManager beanManager) {
        for (Bean<?> bean : eagerBeansList) {
            // note: toString() is important to instantiate the bean
            beanManager.getReference(bean, bean.getBeanClass(), beanManager.createCreationalContext(bean)).toString();
        }
    }

    /**
     * Adds the {@link ProcessShiroAnnotations} annotation to any Bean containing one of the following annotations
     * {@link RequiresAuthentication}, {@link RequiresGuest}, {@link RequiresUser}, {@link RequiresRoles},
     * or {@link RequiresPermissions}.  This allows the {@link ShiroAnnotationInterceptor} to process the
     * Shiro annotations.
     */
    private <X> void registerAuthAnnotations(@Observes @WithAnnotations({
                                                    RequiresAuthentication.class,
                                                    RequiresGuest.class,
                                                    RequiresUser.class,
                                                    RequiresRoles.class,
                                                    RequiresPermissions.class})
                                                ProcessAnnotatedType<X> pat) {

        // wrap this to override the annotations of the class
        final AnnotatedType<X> at = pat.getAnnotatedType();

        pat.setAnnotatedType(new AdditionalAnntoationType<X, ProcessShiroAnnotations>(at, ProcessShiroAnnotations.class) {
            @Override
            public Set<Annotation> getAnnotations() {
                Set<Annotation> original = at.getAnnotations();
                Set<Annotation> annotations = new HashSet<>(original);

                annotations.add(new AnnotationLiteral<ProcessShiroAnnotations>() {});

                return annotations;
            }
        });
    }

    private abstract static class AdditionalAnntoationType<T, X extends Annotation> implements AnnotatedType<T> {

        private final AnnotatedType<T> delegate;
        private final Class<X> extraAnnotation;

        private AdditionalAnntoationType(AnnotatedType<T> delegate, Class<X> extraAnnotation) {
            this.delegate = delegate;
            this.extraAnnotation = extraAnnotation;
        }

        @Override
        public Set<AnnotatedConstructor<T>> getConstructors() {
            return delegate.getConstructors();
        }

        @Override
        public Set<AnnotatedField<? super T>> getFields() {
            return delegate.getFields();
        }

        @Override
        public Class<T> getJavaClass() {
            return delegate.getJavaClass();
        }

        @Override
        public Set<AnnotatedMethod<? super T>> getMethods() {
            return delegate.getMethods();
        }

        @Override
        public <T extends Annotation> T getAnnotation(final Class<T> annType) {
            return delegate.getAnnotation(annType);
        }

        @Override
        public Type getBaseType() {
            return delegate.getBaseType();
        }

        @Override
        public Set<Type> getTypeClosure() {
            return delegate.getTypeClosure();
        }

        @Override
        public boolean isAnnotationPresent(Class<? extends Annotation> annType) {
            return extraAnnotation.equals(annType)
                    || delegate.isAnnotationPresent(annType);
        }

    }

}
