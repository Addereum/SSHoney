package de.addereum.bagofhoney;

import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;

import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

public class Utils {
    /**
     * Creates or loads the SSH host key from disk.
     * The path is configurable via ENV BAGOFHONEY_HOSTKEY (default: ./data/hostkey.ser).
     */
    public static KeyPairProvider createSimpleHostKeyProvider() {
        String env = System.getenv("BAGOFHONEY_HOSTKEY");
        Path keyPath = Paths.get(env != null && !env.isBlank() ? env : "data/hostkey.ser").toAbsolutePath();

        try {
            Files.createDirectories(keyPath.getParent());
        } catch (Exception ignored) {
            // If the parent folder can't be made, let the provider fail loudly later
        }

        // Try to set POSIX permissions if we're on a system that supports it
        try {
            Set<PosixFilePermission> perms = Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            );
            Files.setPosixFilePermissions(keyPath, perms);
        } catch (Exception ignored) {
            // Windows and non-POSIX systems can scream into the void
        }

        return new SimpleGeneratorHostKeyProvider(keyPath);
    }
}
