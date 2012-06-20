package org.apache.shiro.config;

import org.apache.shiro.config.event.*;

import java.util.ArrayList;
import java.util.List;

public class RecordingBeanListener extends BeanListenerSupport {

    private List<InstantiatedBeanEvent> instantiateEvents = new ArrayList<InstantiatedBeanEvent>();
    private List<ConfiguredBeanEvent> configuredEvents = new ArrayList<ConfiguredBeanEvent>();
    private List<DestroyedBeanEvent> destroyedEvents = new ArrayList<DestroyedBeanEvent>();

    private List<BeanEvent> unhandledEvents = new ArrayList<BeanEvent>();

    @Override
    protected void onUnhandledBeanEvent(BeanEvent beanEvent) {
        this.unhandledEvents.add(beanEvent);
    }

    @Override
    protected void onInstantiatedBeanEvent(InstantiatedBeanEvent beanEvent) {
        this.instantiateEvents.add(beanEvent);
    }

    @Override
    protected void onConfiguredBeanEvent(ConfiguredBeanEvent beanEvent) {
        this.configuredEvents.add(beanEvent);
    }

    @Override
    protected void onDestroyedBeanEvent(DestroyedBeanEvent beanEvent) {
        this.destroyedEvents.add(beanEvent);
    }

    public List<InstantiatedBeanEvent> getInstantiateEvents() {
        return instantiateEvents;
    }

    public List<ConfiguredBeanEvent> getConfiguredEvents() {
        return configuredEvents;
    }

    public List<DestroyedBeanEvent> getDestroyedEvents() {
        return destroyedEvents;
    }

    public List<BeanEvent> getUnhandledEvents() {
        return unhandledEvents;
    }
}
