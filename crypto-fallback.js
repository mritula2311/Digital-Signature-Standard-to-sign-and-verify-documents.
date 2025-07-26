// Fallback crypto implementation using Web Crypto API
// This provides compatibility when jsrsasign is not available

const CryptoFallback = {
  // Simple SHA-256 implementation using Web Crypto API
  async sha256(data) {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  },

  // RSA key generation using Web Crypto API
  async generateRSAKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"]
    );

    // Export keys to get their components
    const publicKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

    return {
      prvKeyObj: {
        ...privateKey,
        cryptoKey: keyPair.privateKey
      },
      pubKeyObj: {
        ...publicKey,
        cryptoKey: keyPair.publicKey
      }
    };
  },

  // Sign data using Web Crypto API
  async sign(privateKey, data, algorithm = "RSASSA-PKCS1-v1_5") {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    
    const signature = await crypto.subtle.sign(
      algorithm,
      privateKey.cryptoKey,
      dataBuffer
    );
    
    // Convert to hex string
    const signatureArray = Array.from(new Uint8Array(signature));
    return signatureArray.map(b => b.toString(16).padStart(2, '0')).join('');
  },

  // Verify signature using Web Crypto API
  async verify(publicKey, signature, data, algorithm = "RSASSA-PKCS1-v1_5") {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    
    // Convert hex signature back to buffer
    const signatureBuffer = new Uint8Array(
      signature.match(/.{2}/g).map(byte => parseInt(byte, 16))
    );
    
    // If publicKey is already a CryptoKey, use it directly
    let cryptoKey = publicKey.cryptoKey;
    
    // Check if cryptoKey is empty object or not a real CryptoKey
    if (cryptoKey && typeof cryptoKey === 'object' && Object.keys(cryptoKey).length === 0) {
      cryptoKey = null;
    }
    
    // If we need to import the key from JWK format
    if (!cryptoKey && (publicKey.kty || publicKey.n)) {
      try {
        cryptoKey = await crypto.subtle.importKey(
          "jwk",
          publicKey,
          {
            name: "RSASSA-PKCS1-v1_5",
            hash: "SHA-256",
          },
          false,
          ["verify"]
        );
      } catch (importError) {
        console.error('Key import failed:', importError);
        throw importError;
      }
    }
    
    if (!cryptoKey) {
      throw new Error('Could not create or import CryptoKey');
    }
    
    return await crypto.subtle.verify(
      algorithm,
      cryptoKey,
      signatureBuffer,
      dataBuffer
    );
  }
};

// Fallback implementation that mimics jsrsasign API
if (typeof KEYUTIL === 'undefined') {
  window.KEYUTIL = {
    generateKeypair: async function(type, keySize) {
      // For simplicity, we'll only support RSA in the fallback
      // DSA is more complex and not directly supported by Web Crypto API
      if (type === 'DSA') {
        throw new Error('DSA not supported in fallback mode');
      }
      
      return await CryptoFallback.generateRSAKeyPair();
    }
  };
}

if (typeof KJUR === 'undefined') {
  window.KJUR = {
    crypto: {
      Util: {
        sha256: async function(data) {
          return await CryptoFallback.sha256(data);
        }
      },
      Signature: function(options) {
        this.alg = options.alg;
        this.privateKey = null;
        this.publicKey = null;
        this.data = '';
        
        this.init = function(key) {
          if (key.cryptoKey && key.cryptoKey.type) {
            if (key.cryptoKey.type === 'private') {
              this.privateKey = key;
            } else {
              this.publicKey = key;
            }
          } else if (key.kty || key.n) {
            // This is a JWK format key, store it for later import
            this.publicKey = key;
          } else {
            // Fallback for other key formats
            this.privateKey = key;
            this.publicKey = key;
          }
        };
        
        this.updateString = function(data) {
          this.data = data;
        };
        
        this.sign = async function() {
          return await CryptoFallback.sign(this.privateKey, this.data);
        };
        
        this.verify = async function(signature) {
          return await CryptoFallback.verify(this.publicKey, signature, this.data);
        };
      }
    }
  };
}