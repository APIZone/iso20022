package io.apizone.ips.simulation;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.Objects;

/**
 * @author imsrk
 * @project az-prc-ipsl
 * @timestamp Tuesday, 27-Jul-2021, 07:38
 */

public class KeyStoreInfo {

    private static final String KEY_STORE_TYPE = "PKCS12";

    private final String alias;
    private final String password;
    private KeyStore keyStore;

    /**
     * Instantiates a new Key store info.
     *
     * @param alias    the alias
     * @param password the password
     */
    public KeyStoreInfo(String alias, String password) {
        Objects.requireNonNull(alias, "Alias cannot be null");
        Objects.requireNonNull(password, "Password cannot be null");
        this.alias = alias;
        this.password = password;
    }

    /**
     * Loads KeyStore from the given Private Key
     *
     * @param privateKey the private key
     * @throws RuntimeException the xml signing exception
     */
    public void load(InputStream privateKey) throws Exception {
        Objects.requireNonNull(privateKey, "Private key input stream cannot be NULL");
        try  {
            this.keyStore       = KeyStore.getInstance(KEY_STORE_TYPE);
            this.keyStore.load(privateKey, password.toCharArray());
        } catch (Exception e) {
            throw new RuntimeException("Error loading KeyStore", e);
        }
    }

    /**
     * Gets alias.
     *
     * @return the alias
     */
    public String getAlias() {
        return alias;
    }

    /**
     * Gets password.
     *
     * @return the password
     */
    public String getPassword() {
        return password;
    }

    /**
     * Gets key store.
     *
     * @return the key store
     */
    public KeyStore getKeyStore() {
        return keyStore;
    }

}