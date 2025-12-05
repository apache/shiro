<!--
For Security Vulnerabilities, please email: security@shiro.apache.org
For more details on how to report a vulnerability see: https://www.apache.org/security/
-->

Following this checklist to help us incorporate your contribution quickly and easily:

 - [ ] Make sure there is a [GitHub issue](https://github.com/apache/shiro/issues) filed
       for the change (usually before you start working on it).  Trivial changes like typos do not
       require a GitHub issue.  Your pull request should address just this issue, without pulling in other changes.
 - [ ] Format the pull request title like `[#XXX] - Fixes bug in SessionManager`,
       where you replace `#XXX` with the appropriate GitHub issue. Best practice
       is to use the GitHub issue title in the pull request title and in the first line of the commit message.
 - [ ] Write a pull request description that is detailed enough to understand what the pull request does, how, and why.
 - [ ] add `fixes #XXX` if merging the PR should close a related issue.
 - [ ] Run `mvn verify` to make sure basic checks pass. A more thorough check will be performed on your pull request automatically.
 - [ ] Committers: Make sure a milestone is set on the PR
 - [ ] Committers: Use "Squash and Merge" to combine all commits into one when merging a PR when appropriate.

Trivial changes like typos do not require a GitHub issue (javadoc, comments...).
In this case, just format the pull request title like `[DOC] - Add javadoc in SessionManager`.

If this is your first contribution, you have to read the [Contribution Guidelines](https://github.com/apache/shiro/blob/master/CONTRIBUTING.md)

If your pull request is about ~20 lines of code you don't need to sign an [Individual Contributor License Agreement](https://www.apache.org/licenses/icla.pdf)
if you are unsure please ask on the developers list.

To make clear that you license your contribution under the [Apache License Version 2.0, January 2004](http://www.apache.org/licenses/LICENSE-2.0)
you have to acknowledge this by using the following check-box.

 - [ ] I hereby declare this contribution to be licenced under the [Apache License Version 2.0, January 2004](http://www.apache.org/licenses/LICENSE-2.0)
 - [ ] In any other case, please file an [Apache Individual Contributor License Agreement](https://www.apache.org/licenses/icla.pdf).
