package org.apache.shiro.config.event;

public abstract class BeanListenerSupport implements BeanListener {
    public void onBeanEvent(final BeanEvent beanEvent) {
        if (beanEvent instanceof InstantiatedBeanEvent) {
            this.onInstantiatedBeanEvent((InstantiatedBeanEvent) beanEvent);
        } else if (beanEvent instanceof ConfiguredBeanEvent) {
            this.onConfiguredBeanEvent((ConfiguredBeanEvent) beanEvent);
        } else if (beanEvent instanceof DestroyedBeanEvent) {
            this.onDestroyedBeanEvent((DestroyedBeanEvent) beanEvent);
        } else {
            this.onUnhandledBeanEvent(beanEvent);
        }
    }

    protected void onUnhandledBeanEvent(final BeanEvent beanEvent) {
        // do nothing
    }

    protected void onInstantiatedBeanEvent(final InstantiatedBeanEvent beanEvent) {
        // do nothing
    }

    protected void onConfiguredBeanEvent(final ConfiguredBeanEvent beanEvent) {
        // do nothing
    }

    protected void onDestroyedBeanEvent(final DestroyedBeanEvent beanEvent) {
        // do nothing
    }
}
