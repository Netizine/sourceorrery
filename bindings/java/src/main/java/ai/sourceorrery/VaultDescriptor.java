package ai.sourceorrery;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import ai.sourceorrery.internal.Json;

/**
 * Non-sensitive description of a vault.
 *
 * @param name vault name
 * @param id stable random identifier
 * @param backend backend kind ({@code encrypted-sqlite})
 * @param path on-disk location, if file-backed
 * @param createdOn creation time
 * @param recoveryLevel deletion behaviour for secrets in the vault
 * @param retentionDays soft-delete retention in days
 * @param protectors the kinds of key that open the vault ({@code this-machine},
 *     {@code recovery})
 */
public record VaultDescriptor(
        String name,
        String id,
        String backend,
        Optional<String> path,
        Instant createdOn,
        String recoveryLevel,
        long retentionDays,
        List<String> protectors) {

    static VaultDescriptor fromJson(String json) {
        Map<String, Object> raw = Json.parseObject(json);
        return new VaultDescriptor(
                String.valueOf(raw.get("name")),
                String.valueOf(raw.get("id")),
                String.valueOf(raw.get("backend")),
                Optional.ofNullable((String) raw.get("path")),
                Instant.parse(String.valueOf(raw.get("created_on"))),
                raw.get("recovery_level") instanceof String level ? level : "recoverable",
                raw.get("retention_days") instanceof Long days ? days : 0L,
                SecretProperties.strings(raw.get("protectors")));
    }
}
