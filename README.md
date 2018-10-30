![Logo](images/sc-logo.png)

# opensaml-pkcs11

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.opensaml/opensaml-pkcs11-support/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.opensaml/opensaml-pkcs11-support) [![Known Vulnerabilities](https://snyk.io/test/github/swedenconnect/opensaml-pkcs11/badge.svg?targetFile=pom.xml)](https://snyk.io/test/github/swedenconnect/opensaml-pkcs11?targetFile=pom.xml)

This library provides the capability to create OpenSAML 3 credentials where the private key is stored and operated inside a PKCS#11 token/HSM.

The process to create a PKCS#11 credential involves 2 steps:

1. Create PKCS#11 providers for HSM operated keys
2. Create OpenSAML credentials based on these providers.

#### Maven and documentation

You can either build the library yourself, or include the following in your POM-file:

```
<dependency>
  <groupId>se.swedenconnect.opensaml</groupId>
  <artifactId>opensaml-pkcs11-support</artifactId>
  <version>${pkcs11-support.version}</version>
</dependency>
```

* API documentation for the latest version of opensaml-pkcs11 library - [http://docs.swedenconnect.se/opensaml-pkcs11/javadoc](http://docs.swedenconnect.se/opensaml-pkcs11/javadoc).
* Project information - [http://docs.swedenconnect.se/opensaml-pkcs11/site/](http://docs.swedenconnect.se/opensaml-pkcs11/site).

## Creating PKCS#11 providers

PKCS#11 Providers are created based on PKCS#11 provider configurations. Three different types of configuration options are supported:

1. Providing a list of external configuration files
2. Specifying the parameters of configuration data
3. Providing configuration data for SoftHSM usage for test

The PKCS#11 providers that are created are instances of `sun.security.pkcs11.SunPKCS11` as described in the [Java PKCS#11 Reference Guide](https://docs.oracle.com/javase/7/docs/technotes/guides/security/p11guide.html)

Each private key may be represented by multiple instances of the same key stored in separate HSM modules for redundancy and load balancing. 

The basic structure allows configuration of multiple HSM slots, where each slot holds an identical set of private keys, where each key is identified by its alias. The configuration options provided below is intended to initiate all HSM slots for all available private keys for a service.

### External config
The external config provider is created by an instance of the `PKCS11ProvidedCfgConfiguration` class

Example:

        PKCS11ProviderConfiguration configuration = 
                new PKCS11ProvidedCfgConfiguration(Arrays.asList(
                "/path-to-first-hsm-configuration-file",
                "/path-to-second-hsm-configuration-file"
        ));

Each provided configuration file is formatted according to the [Java PKCS#11 Reference Guide](https://docs.oracle.com/javase/7/docs/technotes/guides/security/p11guide.html).

### Parameter config
Configuration can be provided by providing parameters in an instance of the `PKCS11ProviderConfiguration` class.

Example:

        PKCS11ProviderConfiguration configuration
                = new PKCS11ProviderConfiguration();
        configuration.setName("provider-name");
        configuration.setLibrary("/path-to-pkcs11-library");
        configuration.setSlot("0");
        configuration.setSlotListIndexMaxRange(4);

All parameters are as specified in the [Java PKCS#11 Reference Guide](https://docs.oracle.com/javase/7/docs/technotes/guides/security/p11guide.html), except for the additional parameter SlotListIndexMaxRange. If this parameter is set to a number greater than 0, then all slots ranging from the specified slot up to the slot + maxRange will be tested and instantiated with an individual provider. All slots in this range will be instantiated until either the maxRange is reached or an empty slot is encountered.

### Soft HSM config
SoftHSM is configured by an instance of the `PKCS11SoftHsmProviderConfiguration` class.

Soft HSM implementations do require that the host have 2 components installed:

1. SoftHSM version 2
2. The command line tool pkcs-11-tool

For installation of SoftHSM refer to [SoftHSM on Open DNSSEC](https://www.opendnssec.org/softhsm/)

Installation of pkcs-11-tool can be achieved on linux using the following script:

    apt-get install -y pcscd libccid libpcsclite-dev libssl-dev libreadline-dev autoconf automake build-essential docbook-xsl xsltproc libtool pkg-config
    wget https://github.com/OpenSC/OpenSC/releases/download/0.17.0/opensc-0.17.0.tar.gz
    tar xfvz opensc-*.tar.gz
    cd opensc-0.17.0
    ./bootstrap && ./configure --prefix=/usr --sysconfdir=/etc/opensc
    make && make install
    cd .. && rm -rf opensc*

Example configuration setup for SoftHSM:

        PKCS11ProviderConfiguration configuration
                = new PKCS11SoftHsmProviderConfiguration();
        configuration.setCredentialConfigurationList(
                Arrays.asList(
                        new SoftHsmCredentialConfiguration(
                                "samlsign",
                                "/path-to-key.key",
                                "/path-to-cert.crt")));
        configuration.setPin("1234");
        configuration.setLibrary("/usr/lib/softhsm/libsofthsm2.so");

The `SoftHsmCredentialConfiguration` object holds information about the key that is being loaded into the SoftHSM module on the host.

## Instantiating providers
Providers are instantiated by an instance of `PKCS11ProviderFactory`.

Example:

    PKCS11ProviderFactory factory = new PKCS11ProviderFactory(configuration);
    PKCS11Provider pkcs11Provider = factory.createInstance();


## Creating OpenSAML PKCS#11 credentials

Two credential classes are available

1. PKCS11Credential
2. PKCS11NoTestCredential

Both credential types provide an instance of the requested key by randomly selecting of one of the available keys under the specified alias.

The PKCS11Credential object performs a pre-sign test before using the key. If the connection to the key is lost, the key is reloaded. This credential type is intended for low transaction volume implementations with a high demand for availability. This option means a certain loss of performance capacity due to the key testing activity.

The PKCS11NoTestCredential does not perform any test on the key and does not attempt reloading. This is intended for high volume deployment with redundancy built into the system.

Example:

        PKCS11Provider provider = getProvider();
        Credential credential = new PKCS11Credential(
                x509Cert,
                provider.getProviderNameList(),
                "alias","1234");


------

Copyright &copy; 2018, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).




