/* ========== Secure Key Storage (Session) ========== */

const KeyVault = (() => {
  const PREFIX_WC = 'stego_wc_';
  const PREFIX_RSA = 'stego_rsa_';

  /**
   * Securely store keys in sessionStorage. 
   * This ensures keys don't persist after the browser tab closes, 
   * improving security compared to localStorage, while allowing cross-page navigation.
   */
  function saveKeys(mode, publicKeyPem, privateKeyPem) {
    const prefix = mode === 'webcrypto' ? PREFIX_WC : PREFIX_RSA;
    if (publicKeyPem) sessionStorage.setItem(prefix + 'pub', publicKeyPem);
    if (privateKeyPem) sessionStorage.setItem(prefix + 'priv', privateKeyPem);
  }

  function getKeys(mode) {
    const prefix = mode === 'webcrypto' ? PREFIX_WC : PREFIX_RSA;
    return {
      publicKey: sessionStorage.getItem(prefix + 'pub'),
      privateKey: sessionStorage.getItem(prefix + 'priv')
    };
  }

  function clearKeys(mode) {
    const prefix = mode === 'webcrypto' ? PREFIX_WC : PREFIX_RSA;
    sessionStorage.removeItem(prefix + 'pub');
    sessionStorage.removeItem(prefix + 'priv');
  }

  function hasKeys(mode) {
    const keys = getKeys(mode);
    return !!(keys.publicKey && keys.privateKey);
  }

  return { saveKeys, getKeys, clearKeys, hasKeys };
})();
