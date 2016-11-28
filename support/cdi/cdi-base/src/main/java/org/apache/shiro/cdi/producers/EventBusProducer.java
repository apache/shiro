package org.apache.shiro.cdi.producers;

import org.apache.shiro.event.support.DefaultEventBus;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;

public class EventBusProducer {

    @Produces
    @ApplicationScoped
    DefaultEventBus eventBusWTF(@New DefaultEventBus eventBus) {
        return eventBus;
    }
}
