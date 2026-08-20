package pl.cybertarcza.local;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

final class SecureState {
    private static final String ALIAS = "cybertarcza-state-v1";
    private static final String PREFS = "ct_encrypted_state";
    private static final String VALUE = "vault";
    private static final byte[] AAD = "cybertarcza/android/state/v1".getBytes(StandardCharsets.UTF_8);
    private final SharedPreferences preferences;

    SecureState(Context context) {
        preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    Set<String> load() {
        String envelope = preferences.getString(VALUE, null);
        if (envelope == null || envelope.isEmpty()) return new HashSet<>();
        try {
            String[] parts = envelope.split("\\.", 2);
            if (parts.length != 2) return new HashSet<>();
            byte[] nonce = Base64.decode(parts[0], Base64.NO_WRAP);
            byte[] ciphertext = Base64.decode(parts[1], Base64.NO_WRAP);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(AAD);
            String plaintext = new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
            Set<String> result = new HashSet<>();
            if (!plaintext.isEmpty()) {
                for (String id : plaintext.split(",")) {
                    if (id.matches("[a-z0-9-]{1,40}")) result.add(id);
                }
            }
            return result;
        } catch (Exception ignored) {
            return new HashSet<>();
        }
    }

    void save(Set<String> completed) {
        try {
            String plaintext = String.join(",", completed);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key());
            cipher.updateAAD(AAD);
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            String envelope = Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP) + "." + Base64.encodeToString(ciphertext, Base64.NO_WRAP);
            preferences.edit().putString(VALUE, envelope).commit();
        } catch (Exception exception) {
            throw new IllegalStateException("Nie mozna zapisac zaszyfrowanego stanu", exception);
        }
    }

    private SecretKey key() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (store.containsAlias(ALIAS)) return (SecretKey) store.getKey(ALIAS, null);
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build());
        return generator.generateKey();
    }
}
