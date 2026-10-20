package ai.sourceorrery;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import ai.sourceorrery.internal.Json;

/**
 * Metadata of one version. Never contains the value.
 *
 * @param vault vault the secret lives in
 * @param name secret name
 * @param version opaque version identifier
 * @param enabled whether the version can be read
 * @param contentType content type hint, if any
 * @param tags caller-defined, non-sensitive tags
 * @param notBefore activation time, if any
 * @param expiresOn expiry time, if any
 * @param createdOn creation time
 * @param updatedOn last metadata change
 * @param recoveryLevel {@code recoverable} or {@code purgeable}
 */
public record SecretProperties(
        String vault,
        String name,
        String version,
        boolean enabled,
        Optional<String> contentType,
        Map<String, String> tags,
        Optional<Instant> notBefore,
        Optional<Instant> expiresOn,
        Instant createdOn,
        Instant updatedOn,
        String recoveryLevel) {

    /** {@code sourceorrery://vault/name/version} for exactly this version. */
    public String reference() {
        return "sourceorrery://" + vault + "/" + name + "/" + version;
    }

    static SecretProperties fromJson(String json) {
        return fromMap(Json.parseObject(json));
    }

    static SecretProperties fromMap(Map<String, Object> raw) {
        Map<String, String> tags = new LinkedHashMap<>();
        if (raw.get("tags") instanceof Map<?, ?> rawTags) {
            rawTags.forEach((k, v) -> tags.put(String.valueOf(k), String.valueOf(v)));
        }
        return new SecretProperties(
                string(raw, "vault"),
                string(raw, "name"),
                string(raw, "version"),
                Boolean.TRUE.equals(raw.get("enabled")),
                Optional.ofNullable((String) raw.get("content_type")),
                Collections.unmodifiableMap(tags),
                instant(raw, "not_before"),
                instant(raw, "expires_on"),
                instant(raw, "created_on").orElseThrow(),
                instant(raw, "updated_on").orElseThrow(),
                raw.get("recovery_level") instanceof String level ? level : "recoverable");
    }

    private static String string(Map<String, Object> raw, String key) {
        Object value = raw.get(key);
        return value == null ? "" : String.valueOf(value);
    }

    private static Optional<Instant> instant(Map<String, Object> raw, String key) {
        Object value = raw.get(key);
        return value instanceof String text ? Optional.of(Instant.parse(text)) : Optional.empty();
    }

    /** Protector kinds and other descriptor lists come back as strings. */
    static List<String> strings(Object value) {
        if (value instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        return List.of();
    }
}
