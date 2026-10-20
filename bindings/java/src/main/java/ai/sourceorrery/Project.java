package ai.sourceorrery;

import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import ai.sourceorrery.internal.Json;
import ai.sourceorrery.internal.Native;

/**
 * The secrets a {@code sourceorrery.toml} declares, resolved like
 * {@code sourceorrery run}: every required secret must resolve or
 * {@link #load} throws that secret's exception; optional secrets that are
 * missing, refused by policy or whose vault does not exist are left out.
 */
public final class Project implements AutoCloseable {
    private final String name;
    private final String manifestPath;
    private final List<ProjectSecret> secrets;

    private Project(String name, String manifestPath, List<ProjectSecret> secrets) {
        this.name = name;
        this.manifestPath = manifestPath;
        this.secrets = Collections.unmodifiableList(secrets);
    }

    /** Load the nearest {@code sourceorrery.toml} above the current directory with the CLI's defaults. */
    public static Project load() {
        return load(Optional.empty(), OpenOptions.defaults());
    }

    /** Load {@code manifest} with the CLI's defaults. */
    public static Project load(String manifest) {
        return load(Optional.ofNullable(manifest), OpenOptions.defaults());
    }

    /** Load {@code manifest} (empty: discover it) with options that apply to every vault the manifest names. */
    public static Project load(Optional<String> manifest, OpenOptions options) {
        MemorySegment handle = Native.projectLoad(manifest.orElse(null), options.toJson(), options.passphraseBytes());
        List<ProjectSecret> secrets = new ArrayList<>();
        try {
            Map<String, Object> info = Json.parseObject(Native.projectInfo(handle));
            long count = Native.projectCount(handle);
            for (long index = 0; index < count; index++) {
                Native.SecretParts parts = Native.projectEntry(handle, index);
                Map<String, Object> entry = Json.parseObject(parts.propertiesJson());
                @SuppressWarnings("unchecked")
                Map<String, Object> properties = (Map<String, Object>) entry.get("properties");
                secrets.add(new ProjectSecret(
                        String.valueOf(entry.get("name")),
                        String.valueOf(entry.get("env")),
                        String.valueOf(entry.get("reference")),
                        Boolean.TRUE.equals(entry.get("required")),
                        SecretProperties.fromMap(properties),
                        new SecretValue(parts.value())));
            }
            return new Project(String.valueOf(info.get("name")), String.valueOf(info.get("manifest_path")), secrets);
        } catch (RuntimeException e) {
            secrets.forEach(s -> s.value().close());
            throw e;
        } finally {
            Native.projectFree(handle);
        }
    }

    /** {@code [project].name}. */
    public String name() {
        return name;
    }

    /** The manifest file that was loaded. */
    public String manifestPath() {
        return manifestPath;
    }

    /** Every secret that resolved, in manifest order. */
    public List<ProjectSecret> secrets() {
        return secrets;
    }

    /** The entry declared as {@code [secrets.<name>]}, if it resolved. */
    public Optional<ProjectSecret> get(String name) {
        return secrets.stream().filter(s -> s.name().equals(name)).findFirst();
    }

    /** The value delivered in environment variable {@code variable}, if any. */
    public Optional<SecretValue> env(String variable) {
        return secrets.stream().filter(s -> s.env().equals(variable)).map(ProjectSecret::value).findFirst();
    }

    /** Zeroise every value. */
    @Override
    public void close() {
        secrets.forEach(s -> s.value().close());
    }
}
