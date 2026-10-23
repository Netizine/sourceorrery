package ai.sourceorrery;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import ai.sourceorrery.internal.Native;

/** The Java SDK against the vault created by scripts/ci/fixture-vault.sh. */
class ReaderTest {
    static String home;
    static String passphrase;
    static String vault;
    static String manifest;
    static String oldVersion;
    static final String LATEST = "ci-secret-value";
    static final String FIRST = "first-version";

    @BeforeAll
    static void fixture() {
        home = System.getenv("SOURCEORRERY_HOME");
        passphrase = System.getenv("SOURCEORRERY_PASSPHRASE");
        vault = System.getenv("SOURCEORRERY_TEST_VAULT");
        manifest = System.getenv("SOURCEORRERY_TEST_MANIFEST");
        oldVersion = System.getenv("SOURCEORRERY_TEST_OLD_VERSION");
        assumeTrue(home != null && vault != null && manifest != null && oldVersion != null,
                "run scripts/ci/fixture-vault.sh first");
    }

    /** Unlocks through SOURCEORRERY_PASSPHRASE from the environment, like the CLI. */
    private static SecretReader openReader() {
        return SecretReader.open(vault);
    }

    @Test
    void contractVersion() {
        assertEquals("1", SourceOrrery.contractVersion());
        assertEquals(1, SourceOrrery.abiVersion());
    }

    @Test
    void getReturnsTheNewestAccessibleVersion() {
        try (SecretReader reader = openReader(); Secret secret = reader.get("database-password")) {
            assertEquals(LATEST, secret.value().exposeText());
            assertEquals(LATEST, new String(secret.value().expose(), StandardCharsets.UTF_8));
            assertEquals(LATEST.length(), secret.value().length());
            secret.value().use(bytes -> assertEquals(LATEST.length(), bytes.length));
            SecretProperties p = secret.properties();
            assertEquals("database-password", p.name());
            assertEquals(vault, p.vault());
            assertTrue(p.enabled());
            assertEquals(Optional.of("text/plain"), p.contentType());
            assertEquals(Map.of("env", "ci"), p.tags());
            assertFalse(p.createdOn().isAfter(Instant.now()));
            assertEquals("sourceorrery://" + vault + "/database-password/" + p.version(), p.reference());
        }
    }

    @Test
    void explicitVersionsAndProperties() {
        try (SecretReader reader = openReader(); Secret old = reader.get("database-password", oldVersion)) {
            assertEquals(FIRST, old.value().exposeText());
            assertEquals(oldVersion, old.properties().version());
            assertEquals(oldVersion, reader.properties("database-password", Optional.of(oldVersion)).version());
            assertNotEquals(oldVersion, reader.properties("database-password").version());
        }
    }

    @Test
    void referencesResolveWithinTheVault() {
        try (SecretReader reader = openReader()) {
            try (Secret latest = reader.resolve("sourceorrery://" + vault + "/database-password")) {
                assertEquals(LATEST, latest.value().exposeText());
            }
            try (Secret pinned = reader.resolve("sourceorrery://" + vault + "/database-password/" + oldVersion)) {
                assertEquals(FIRST, pinned.value().exposeText());
            }
            InvalidArgumentException err = assertThrows(InvalidArgumentException.class,
                    () -> reader.resolve("sourceorrery://other-vault/database-password"));
            assertEquals("invalid_argument", err.code());
            assertThrows(InvalidArgumentException.class, () -> reader.resolve("not-a-reference"));
        }
    }

    @Test
    void disabledNewestVersionFallsBack() {
        try (SecretReader reader = openReader(); Secret current = reader.get("rotated-key")) {
            assertEquals("old", current.value().exposeText());
            SecretProperties newest = reader.properties("rotated-key");
            assertFalse(newest.enabled());
            SecretDisabledException err = assertThrows(SecretDisabledException.class,
                    () -> reader.get("rotated-key", newest.version()));
            assertInstanceOf(PolicyException.class, err);
            assertEquals("disabled", err.code());
            assertTrue(err.hint().contains("--enable"));
        }
    }

    @Test
    void policyErrorsExplainThemselves() {
        try (SecretReader reader = openReader()) {
            SecretExpiredException expired = assertThrows(SecretExpiredException.class, () -> reader.get("expired-token"));
            assertTrue(expired.hint().startsWith("Policy"));
            assertFalse(expired.isTransient());
            SecretNotYetValidException pending = assertThrows(SecretNotYetValidException.class, () -> reader.get("future-token"));
            assertTrue(pending.isTransient());
            SecretDeletedException deleted = assertThrows(SecretDeletedException.class, () -> reader.get("deleted-secret"));
            assertTrue(deleted.hint().contains("secret recover deleted-secret"));
        }
    }

    @Test
    void missingSecretsSayHowToStoreThem() {
        try (SecretReader reader = openReader()) {
            SecretNotFoundException err = assertThrows(SecretNotFoundException.class, () -> reader.get("missing"));
            assertEquals("not_found", err.code());
            assertEquals("secret 'missing' was not found", err.detail());
            assertTrue(err.hint().contains("sourceorrery secret set missing --vault " + vault));
            assertTrue(err.getMessage().startsWith(err.detail() + ". "));
            VersionNotFoundException version = assertThrows(VersionNotFoundException.class,
                    () -> reader.get("database-password", "deadbeef"));
            assertInstanceOf(SecretNotFoundException.class, version);
            assertThrows(InvalidNameException.class, () -> reader.get("bad_name"));
        }
    }

    @Test
    void vaultErrorsSayHowToFixThem() {
        VaultNotFoundException missing = assertThrows(VaultNotFoundException.class, () -> SecretReader.open("no-such-vault"));
        assertTrue(missing.hint().contains("sourceorrery vault create no-such-vault"));
        assertTrue(missing.hint().contains(home));

        OpenOptions wrong = OpenOptions.defaults().withPassphrase("wrong-passphrase").withEnvironment(false);
        VaultLockedException locked = assertThrows(VaultLockedException.class, () -> SecretReader.open(vault, wrong));
        assertTrue(locked.hint().contains("passphrase option: tried"));
        assertTrue(locked.hint().contains("SOURCEORRERY_PASSPHRASE: not set"));
        assertTrue(locked.hint().contains("--vault " + vault));
        assertFalse(locked.getMessage().contains("wrong-passphrase"));

        OpenOptions explicit = OpenOptions.defaults().withHome(home).withPassphrase(passphrase).withEnvironment(false);
        SecretReader reader = SecretReader.open(vault, explicit);
        assertEquals(vault, reader.vaultName());
        VaultDescriptor descriptor = reader.descriptor();
        assertEquals(vault, descriptor.name());
        assertEquals(List.of("passphrase"), descriptor.protectors());
        reader.close();
        assertTrue(reader.isClosed());
        assertThrows(IllegalStateException.class, () -> reader.get("database-password"));
        reader.close();
    }

    @Test
    void secretValuesDoNotLeak() {
        try (SecretReader reader = openReader()) {
            Secret secret = reader.get("database-password");
            assertEquals("[REDACTED]", secret.value().toString());
            assertFalse(secret.toString().contains(LATEST));
            assertFalse(secret.properties().toString().contains(LATEST));
            secret.value().close();
            assertTrue(secret.value().isClosed());
            assertEquals(0, secret.value().length());
            assertThrows(IllegalStateException.class, () -> secret.value().expose());
            secret.value().close();
        }
    }

    @Test
    void readerIsThreadSafe() throws Exception {
        try (SecretReader reader = openReader(); ExecutorService pool = Executors.newFixedThreadPool(4)) {
            List<Future<Boolean>> results = pool.invokeAll(java.util.Collections.nCopies(4, () -> {
                for (int i = 0; i < 5; i++) {
                    try (Secret secret = reader.get("database-password")) {
                        if (!LATEST.equals(secret.value().exposeText())) {
                            return false;
                        }
                    }
                }
                try {
                    reader.get("missing");
                    return false;
                } catch (SecretNotFoundException expected) {
                    return true;
                }
            }));
            for (Future<Boolean> result : results) {
                assertTrue(result.get());
            }
        }
    }

    @Test
    void projectLoadMirrorsRun() {
        try (Project project = Project.load(manifest)) {
            assertEquals("ci-project", project.name());
            assertTrue(project.manifestPath().endsWith("sourceorrery.toml"));
            assertEquals(List.of("database-password", "rotated-key"),
                    project.secrets().stream().map(ProjectSecret::name).sorted().toList());
            assertEquals(LATEST, project.env("DATABASE_PASSWORD").orElseThrow().exposeText());
            assertEquals("old", project.env("ROTATED").orElseThrow().exposeText());
            assertTrue(project.get("missing-optional").isEmpty(), "optional misses are skipped");
            assertTrue(project.get("expired-token").isEmpty(), "optional policy refusals are skipped");
            ProjectSecret entry = project.get("rotated-key").orElseThrow();
            assertTrue(entry.required());
            assertEquals("ROTATED", entry.env());
            assertEquals("sourceorrery://" + vault + "/rotated-key", entry.reference());
            assertEquals(2, project.secrets().size());
        }
        assertThrows(ManifestException.class, () -> Project.load(manifest + ".missing"));
        OpenOptions wrong = OpenOptions.defaults().withPassphrase("wrong").withEnvironment(false);
        assertThrows(VaultLockedException.class, () -> Project.load(Optional.of(manifest), wrong));
    }

    /**
     * A vault the manifest declares in {@code [vaults.<name>]} goes to its provider, whose credential
     * comes from the environment, never the manifest.
     */
    @Test
    void manifestDeclaresRemoteVaults(@TempDir Path dir) throws Exception {
        Path remoteManifest = dir.resolve("sourceorrery.toml");
        Files.writeString(remoteManifest, String.join("\n",
                "[project]",
                "name = \"demo\"",
                "vault = \"" + vault + "\"",
                "",
                "[vaults.remote-x]",
                "provider = \"hashicorp-vault\"",
                "address = \"http://127.0.0.1:1\"",
                "mount = \"secret\"",
                ""));
        OpenOptions options = OpenOptions.defaults().withManifest(remoteManifest);
        assertEquals(Optional.of(remoteManifest.toString()), options.manifest());
        assertTrue(options.toJson().contains("\"manifest\":"));

        // Nothing listens on port 1. Without a Vault credential (VAULT_TOKEN, ~/.vault-token, AppRole,
        // ...) the provider refuses before any request; with one it fails to connect. Java cannot set
        // environment variables in-process, so whichever the environment produces is accepted, as long
        // as the code matches the class and the message names the provider.
        SourceOrreryException err = assertThrows(SourceOrreryException.class, () -> SecretReader.open("remote-x", options));
        assertTrue(err.detail().contains("hashicorp-vault"), err.detail());
        switch (err) {
            case UnauthenticatedException unauthenticated -> {
                assertEquals("unauthenticated", unauthenticated.code());
                assertFalse(unauthenticated.isTransient());
                assertTrue(unauthenticated.detail().contains("not authenticated to hashicorp-vault"), unauthenticated.detail());
                assertTrue(unauthenticated.hint().contains("VAULT_TOKEN"), unauthenticated.hint());
            }
            case ProviderUnavailableException unavailable -> {
                assertEquals("provider_unavailable", unavailable.code());
                assertTrue(unavailable.isTransient());
                assertTrue(unavailable.detail().contains("hashicorp-vault is unavailable"), unavailable.detail());
                assertTrue(unavailable.hint().contains("[vaults.remote-x]"), unavailable.hint());
            }
            default -> fail("expected UnauthenticatedException or ProviderUnavailableException, got "
                    + err.getClass().getName() + " (" + err.code() + "): " + err.getMessage());
        }

        // A vault without a table is still the local file.
        try (SecretReader reader = SecretReader.open(vault, options); Secret secret = reader.get("database-password")) {
            assertEquals(vault, reader.vaultName());
            assertEquals(LATEST, secret.value().exposeText());
        }
    }

    @Test
    void remoteCodesMapToTheirExceptions() {
        SourceOrreryException unauthenticated = SourceOrreryException.forCode("unauthenticated", "m", "h");
        assertInstanceOf(UnauthenticatedException.class, unauthenticated);
        assertEquals("unauthenticated", unauthenticated.code());
        assertFalse(unauthenticated.isTransient());
        SourceOrreryException unavailable = SourceOrreryException.forCode("provider_unavailable", "m", "h");
        assertInstanceOf(ProviderUnavailableException.class, unavailable);
        assertEquals("provider_unavailable", unavailable.code());
        assertTrue(unavailable.isTransient());
    }

    @Test
    void unknownCodesKeepTheirCode() {
        SourceOrreryException err = SourceOrreryException.forCode("brand_new_code", "m", "h");
        assertEquals(SourceOrreryException.class, err.getClass());
        assertEquals("brand_new_code", err.code());
        assertEquals("m. h", err.getMessage());
    }

    /** An SDK refuses a library built for another C ABI version with a typed exception (ADR 0007). */
    @Test
    void abiMismatchIsATypedException() {
        assertEquals(Native.ABI_VERSION, Native.abiVersion(), "the installed library matches");
        assertTrue(Native.abiMismatch(Native.ABI_VERSION) == null);
        SourceOrreryException err = Native.abiMismatch(Native.ABI_VERSION + 1);
        assertEquals("abi_mismatch", err.code());
        assertTrue(err.getMessage().contains(String.valueOf(Native.ABI_VERSION + 1)));
        assertTrue(err.getMessage().contains(String.valueOf(Native.ABI_VERSION)));
        assertTrue(err.hint().contains("sourceorrery-ffi"));
    }
}
