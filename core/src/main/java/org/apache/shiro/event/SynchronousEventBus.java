package org.apache.shiro.event;

import org.apache.shiro.util.Assert;

import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * @since 1.3
 */
public class SynchronousEventBus implements Publisher, SubscriberRegistry {

    private final InternalRegistry registry;

    public SynchronousEventBus() {
        this.registry = new InternalRegistry();
    }

    public void publish(Object event) {
        if (event == null) {
            return;
        }
        Class eventClass = event.getClass();
        Set<Class> keys = registry.keySet();
        for( Class clazz : keys) {
            if (clazz.isAssignableFrom(eventClass)) {
                List<Subscriber> subscribers = registry.get(clazz);
                if (subscribers != null) {
                    for (Subscriber subscriber : subscribers) {
                        subscriber.onEvent(event);
                    }
                }
            }
        }
    }

    public void subscribe(Subscriber subscriber) {
        subscribe(subscriber, Object.class);
    }

    public void subscribe(Subscriber subscriber, Class... types) {
        Assert.notNull(subscriber, "Subscriber argument cannot be null.");
        types = (types != null && types.length > 0) ? types : new Class[]{Object.class};

        for(Class clazz : types) {
            this.registry.subscribe(clazz, subscriber);
        }
    }

    public void unsubscribe(Subscriber subscriber) {
        unsubscribe(subscriber, (Class[])null);
    }

    public void unsubscribe(Subscriber subscriber, Class... types) {
        if (subscriber == null) {
            return;
        }
        if (types == null) {
            this.registry.unsubscribe(subscriber);
        } else {
            for (Class clazz : types) {
                this.registry.unsubscribe(clazz, subscriber);
            }
        }
    }

    private static class SubscribedClassComparator implements Comparator<Class> {

        public int compare(Class a, Class b) {
            if (a == null) {
                if (b == null) {
                    return 0;
                } else {
                    return -1;
                }
            } else if (b == null) {
                return 1;
            } else if (a == b || a.equals(b)) {
                return 0;
            } else {
                if (a.isAssignableFrom(b)) {
                    return 1;
                } else if (b.isAssignableFrom(a)) {
                    return -1;
                } else {
                    return 0;
                }
            }
        }
    }

    private static class InternalRegistry implements Map<Class, List<Subscriber>> {

        private final Lock readLock;
        private final Lock writeLock;
        private final Map<Class,List<Subscriber>> map;

        private InternalRegistry() {
            this.map = new TreeMap<Class, List<Subscriber>>(new SubscribedClassComparator());
            ReentrantReadWriteLock rwl = new ReentrantReadWriteLock();
            readLock = rwl.readLock();
            writeLock = rwl.writeLock();
        }

        public int size() {
            readLock.lock();
            try {
                return map.size();
            } finally {
                readLock.unlock();
            }
        }

        public boolean isEmpty() {
            readLock.lock();
            try {
                return map.isEmpty();

            } finally {
                readLock.unlock();
            }
        }

        public boolean containsKey(Object o) {
            readLock.lock();
            try {
                return map.containsKey(o);
            } finally {
                readLock.unlock();
            }
        }

        public boolean containsValue(Object o) {
            readLock.lock();
            try {
                return map.containsValue(o);
            } finally {
                readLock.unlock();
            }
        }

        public List<Subscriber> get(Object o) {
            readLock.lock();
            try {
                return map.get(o);
            } finally {
                readLock.unlock();
            }
        }

        public List<Subscriber> put(Class c, List<Subscriber> subscribers) {
            writeLock.lock();
            try {
                return this.map.put(c, subscribers);
            } finally {
                writeLock.unlock();
            }
        }

        public List<Subscriber> remove(Object o) {
            writeLock.lock();
            try {
                return this.map.remove(o);
            } finally {
                writeLock.unlock();
            }
        }

        public void putAll(Map<? extends Class, ? extends List<Subscriber>> map) {
            writeLock.lock();
            try {
                this.map.putAll(map);
            } finally {
                writeLock.unlock();
            }
        }

        public void subscribe(Class c, Subscriber s) {
            writeLock.lock();
            try {
                List<Subscriber> subscribers = this.map.get(c);
                if (subscribers == null) {
                    subscribers = new ArrayList<Subscriber>();
                    this.map.put(c, subscribers);
                }
                if (!subscribers.contains(s)) {
                    subscribers.add(s);
                }
            } finally {
                writeLock.unlock();
            }
        }

        public void unsubscribe(Class c, Subscriber s) {
            writeLock.lock();
            try {
                List<Subscriber> subscribers = this.map.get(c);
                if (subscribers != null) {
                    subscribers.remove(s);
                }
            } finally {
                writeLock.unlock();
            }
        }

        public void unsubscribe(Subscriber s) {
            writeLock.lock();
            try {
                for(Map.Entry<Class,List<Subscriber>> entry : this.map.entrySet()) {
                    List<Subscriber> subscribers = entry.getValue();
                    subscribers.remove(s);
                }
            } finally {
                writeLock.unlock();
            }
        }

        public void clear() {
            writeLock.lock();
            try {
                map.clear();
            } finally {
                writeLock.unlock();
            }
        }

        public Set<Class> keySet() {
            readLock.lock();
            try {
                return Collections.unmodifiableSet(map.keySet());
            } finally {
                readLock.unlock();
            }
        }

        public Collection<List<Subscriber>> values() {
            readLock.lock();
            try {
                return Collections.unmodifiableCollection(map.values());
            } finally {
                readLock.unlock();
            }
        }

        public Set<Entry<Class, List<Subscriber>>> entrySet() {
            readLock.lock();
            try {
                return Collections.unmodifiableSet(map.entrySet());
            } finally {
                readLock.unlock();
            }
        }
    }
}
