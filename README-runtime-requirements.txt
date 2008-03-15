JSecurity Runtime Requirements
------------------------------

All 3rd party libraries mentioned below are in this distro's lib directory if you don't already have them.

Required jars
-------------
Ensure jsecurity.jar and Apache commons-logging.jar are in your application's classpath.

JDK 1.3 and 1.4 only: you must include retroweaver.jar and its associated dependendencies
(they can be found in this distro's lib/retroweaver directory).


Feature-based dependencies
--------------------------
- If you want to use JSecurity's enterprise session management:
  . JDK 1.5+: include ehcache.jar
  . JDK 1.3 or 1.4: include ehcache.jar, jug.jar and jug-native.zip

- JSecurity Web Filter text-based config ('config' init param) in web.xml:
- JSecurity code Annotations:
  . include Jakarta commons-beanutils-core.jar
