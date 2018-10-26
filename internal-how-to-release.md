![Logo](images/sc-logo.png)

# opensaml-pkcs11

## Internal Release Guide

The steps for making a new release of the opensaml-pkcs11 library:

* Create a release branch and check it out.
	* The branch name should be `release/x.y.z-release`, e.g. `release/1.2.1-release`.

* Change the version in the POM to the version we are releasing. 
	* Ensure that there are no snapshot-dependencies in the POM.
	
* Build for release:

```
>mvn clean install site -Prelease
```

* Ensure that there is no test-errors, and that the Javadoc-generation succeeded. If not, fix it.

* Also check that the site-generation is successful. Open the generated documentation (target/site/index.html), and especially check that we have 100% dependency convergence. If not, fix it.

* Copy the Javadoc for publishing:

```
>cp -r target/apidocs/* docs/javadoc
>
>mkdir docs/javadoc-versions/<ver>
>cp -r target/apidocs/* docs/javadoc-versions/<ver>
```

* Copy the site documentation:

```
>cp -r target/site/* docs/site
```

* Add and commit all changes:

```
>git add .
>git commit -m "<ver> release"
```

* Tag the release:

```
>git tag -a <ver>-release -m "<ver> release"
>git push origin --tags
```

* Deploy the artifacts (jar, pom, javadoc and sources) to Maven central (you will be prompted for signing key PIN):

```
>mvn clean deploy -Prelease

... will take some time

>mvn nexus-staging:release -Prelease
```

* We are done! Now make a Pull Request and merge to master.
