TODO
====

* compress `core` and `web` to match the other support modules
  maybe just make dependency on shiro-web optional.
* confirm the use of the javax artifacts over geronimo
  [@bdemers] is heavily bias for javax as guice uses javax.inject
* Think about Unit Tests, these seem to all be ITs (PaxExam).  This may be fine in this context, but it makes it difficult to test other CDI containers.
  The original PAX source, used Maven profiles, which required multiple maven executions. (which means we will not be running those tests all the time (i.e. durring release)
* For initial version we _should_ target a single CDI container, much like all of the examples use jetty.
* rename `impl' package to be consistent with other packages in Shiro 