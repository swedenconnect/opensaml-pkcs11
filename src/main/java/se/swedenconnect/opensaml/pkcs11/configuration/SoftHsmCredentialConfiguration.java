package se.swedenconnect.opensaml.pkcs11.configuration;

/**
 * Configuration Class for setting up key and certificates to be loaded into Soft HSM
 *
 * @author Stefan Santesson (stefan@idsec.se)
 * @author Martin Lindström (martin@idsec.se)
 *
 */
public class SoftHsmCredentialConfiguration {
    /**
     * The name of the key. This name will be part of the PKCS#11 provider name used to access the key through Soft HSM
     */
    private String name;
    /**
     * The absolute path to a PEM encoded PKCS#8 key.
     */
    private String keyLocation;
    /**
     * The absolute path to a PEM encoded X509 certificate for the specified key.
     */
    private String certLocation;

    /**
     * Constructor for the Soft HSM key credential
     */
    public SoftHsmCredentialConfiguration() {
    }

    /**
     * Constructor for the Soft HSM key credential
     *
     * @param name The name of the key. This name will be part of the PKCS#11 provider name used to access the key through Soft HSM
     * @param keyLocation The absolute path to a PEM encoded PKCS#8 key
     * @param certLocation The absolute path to a PEM encoded X509 certificate for the specified key
     */
    public SoftHsmCredentialConfiguration(String name, String keyLocation, String certLocation) {
        this.name = name;
        this.keyLocation = keyLocation;
        this.certLocation = certLocation;
    }

    /**
     * Getter for the name of the credential key.
     * @return name
     */
    public String getName() {
        return name;
    }

    /**
     * Setter for the name of the credential key.
     * @param name name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Getter for the credential key location
     * @return credential key location
     */
    public String getKeyLocation() {
        return keyLocation;
    }

    /**
     * Setter for credential key location
     * @param keyLocation credential key location
     */
    public void setKeyLocation(String keyLocation) {
        this.keyLocation = keyLocation;
    }

    /**
     * Getter for the credential cert location
     * @return credential cert location
     */
    public String getCertLocation() {
        return certLocation;
    }

    /**
     * Setter for the credential cert location
     * @param certLocation credential cert location
     */
    public void setCertLocation(String certLocation) {
        this.certLocation = certLocation;
    }

    @Override
    public String toString() {
        return String.format("SoftHSMCredentialConfig: (%s, keyLocation='%s', certLocation='%s')", name, keyLocation, certLocation);
    }
}
