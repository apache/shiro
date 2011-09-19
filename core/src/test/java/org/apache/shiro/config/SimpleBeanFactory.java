package org.apache.shiro.config;

import org.apache.shiro.util.Factory;

public class SimpleBeanFactory implements Factory<SimpleBean> {
    private int factoryInt;
    private String factoryString;

    public SimpleBean getInstance() {
        final SimpleBean simpleBean = new SimpleBean();
        simpleBean.setIntProp(factoryInt);
        simpleBean.setStringProp(factoryString);
        return simpleBean;
    }

    public int getFactoryInt() {
        return factoryInt;
    }

    public void setFactoryInt(int factoryInt) {
        this.factoryInt = factoryInt;
    }

    public String getFactoryString() {
        return factoryString;
    }

    public void setFactoryString(String factoryString) {
        this.factoryString = factoryString;
    }
}
