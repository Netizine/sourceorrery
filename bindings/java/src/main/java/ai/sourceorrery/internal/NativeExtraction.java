package ai.sourceorrery.internal;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Copies the native library bundled in the jar to a file it can be loaded
 * from. Kept apart from {@link Native} so it can be tested without loading
 * a library.
 *
 * <p>Each extraction gets a new directory with a random name, created
 * atomically by {@link Files#createTempDirectory}: nothing can be planted in
 * it beforehand, and an existing directory is never reused. It is created
 * for this process's user only, so another user can neither read the library
 * nor replace it before {@link System#load} opens it: {@code rwx------} on a
 * POSIX file system, and on Windows an access list allowing only that user,
 * which what is copied into it inherits. Windows' temporary directory is
 * not always the user's alone (a tool's group may have access there, or
 * {@code java.io.tmpdir} may name a shared one), so nothing is inherited from
 * it. A file system with neither is refused; {@code SOURCEORRERY_NATIVE_DIR}
 * names a library to load instead.
 */
final class NativeExtraction {
    private NativeExtraction() {}

    static final String PREFIX = "sourceorrery-native";

    private static final Set<PosixFilePermission> OWNER_ONLY = PosixFilePermissions.fromString("rwx------");

    static Path extract(InputStream stream, String file) throws IOException {
        Path dir = privateDirectory();
        // deleteOnExit runs in reverse order of registration: the file goes
        // first, then the directory once it is empty. A Windows DLL that is
        // still loaded at exit cannot be deleted and is left behind.
        dir.toFile().deleteOnExit();
        Path extracted = dir.resolve(file);
        extracted.toFile().deleteOnExit();
        // No REPLACE_EXISTING: in a new directory an existing entry means
        // something else wrote there, and the copy fails instead of loading it.
        Files.copy(stream, extracted);
        return extracted;
    }

    static Path privateDirectory() throws IOException {
        Set<String> views = FileSystems.getDefault().supportedFileAttributeViews();
        if (views.contains("posix")) {
            FileAttribute<Set<PosixFilePermission>> ownerOnly = PosixFilePermissions.asFileAttribute(OWNER_ONLY);
            return Files.createTempDirectory(PREFIX, ownerOnly);
        }
        if (views.contains("acl")) {
            UserPrincipal user = currentUser();
            Path dir = Files.createTempDirectory(PREFIX, userOnly(user));
            // The directory's owner is the user the process runs as. Another
            // principal answering to the same name must not be the one let in.
            if (!Files.getOwner(dir).equals(user)) {
                Files.delete(dir);
                throw new IOException("the user '" + user.getName() + "' found for user.name does not own "
                        + "the directories this process creates; set SOURCEORRERY_NATIVE_DIR");
            }
            return dir;
        }
        throw new IOException("the file system has neither POSIX permissions nor access lists to keep the "
                + "library private; set SOURCEORRERY_NATIVE_DIR");
    }

    private static UserPrincipal currentUser() throws IOException {
        String name = System.getProperty("user.name");
        try {
            return FileSystems.getDefault().getUserPrincipalLookupService().lookupPrincipalByName(name);
        } catch (UserPrincipalNotFoundException e) {
            throw new IOException("cannot find the user '" + name + "' to keep the library private; "
                    + "set SOURCEORRERY_NATIVE_DIR", e);
        }
    }

    /** An access list allowing {@code user} everything, inherited by files and directories created inside. */
    private static FileAttribute<List<AclEntry>> userOnly(UserPrincipal user) {
        List<AclEntry> acl = List.of(AclEntry.newBuilder()
                .setType(AclEntryType.ALLOW)
                .setPrincipal(user)
                .setPermissions(EnumSet.allOf(AclEntryPermission.class))
                .setFlags(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT)
                .build());
        return new FileAttribute<>() {
            @Override
            public String name() {
                return "acl:acl";
            }

            @Override
            public List<AclEntry> value() {
                return acl;
            }
        };
    }
}
