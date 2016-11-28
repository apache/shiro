package org.apache.shiro.cdi.producers;

import org.apache.shiro.session.mgt.SessionFactory;
import org.apache.shiro.session.mgt.SimpleSessionFactory;

import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;

public class SessionFactoryProducer {

    @Produces
    protected SessionFactory sessionFactory(@New SimpleSessionFactory sessionFactory) {
        return sessionFactory;
    }
}
