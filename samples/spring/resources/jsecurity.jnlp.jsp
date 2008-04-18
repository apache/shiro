<%@ page contentType="application/x-java-jnlp-file" %>

<?xml version="1.0" encoding="utf-8"?>
<!-- JNLP File for JSecurity Sample Application -->
<jnlp spec="1.0+" codebase="${codebaseUrl}">
    <information>
        <title>JSecurity Sample Application</title>
        <vendor>JSecurity</vendor>
        <homepage href="http://www.jsecurity.org"/>
        <description>JSecurity Sample Application</description>
        <description kind="short">A webstart application used to demonstrate JSecurity session and security
            management.</description>
        <icon kind="splash" href="logo.png"/>
        <offline-allowed/>
    </information>
    <security>
        <all-permissions/>
    </security>
    <resources>
        <j2se version="1.5"/>
        <jar href="jsecurity-spring-sample.jar"/>
        <jar href="jsecurity.jar"/>
        <jar href="spring.jar"/>
        <jar href="commons-logging.jar"/>
        <property name="jsecurity.session.id" value="${sessionId}"/>
    </resources>
    <application-desc main-class="org.jsecurity.samples.spring.ui.WebStartDriver"/>
</jnlp>