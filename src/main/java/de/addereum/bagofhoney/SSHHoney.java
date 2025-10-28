package de.addereum.bagofhoney;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.command.CommandFactory;
import org.apache.sshd.server.command.CommandLifecycle;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.keyboard.InteractiveChallenge;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.concurrent.*;

public class SSHHoney {
    private static final Logger log = LoggerFactory.getLogger(SSHHoney.class);
    private final HikariDataSource ds;
    private final ExecutorService executor;

    public SSHHoney(String jdbcUrl, String dbUser, String dbPass) {
        HikariConfig cfg = new HikariConfig();
        cfg.setJdbcUrl(jdbcUrl);
        cfg.setUsername(dbUser);
        cfg.setPassword(dbPass);
        cfg.setMaximumPoolSize(5);
        this.ds = new HikariDataSource(cfg);

        this.executor = Executors.newFixedThreadPool(20, r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });
    }

    public void start(int port) throws Exception {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setKeyPairProvider(Utils.createSimpleHostKeyProvider());

        sshd.getProperties().put("idle-timeout", String.valueOf(TimeUnit.MINUTES.toMillis(2)));
        sshd.getProperties().put("auth-timeout", String.valueOf(TimeUnit.MINUTES.toMillis(1)));

        // Because using real authentication logic in a honeypot would be too productive, right?
        sshd.setPasswordAuthenticator((username, password, session) -> {
            logAuthAttempt(session, username, password);
            return true; // LOL sure, everyone's welcome! Here's the red carpet, please hack me.
        });

        sshd.setKeyboardInteractiveAuthenticator(new KeyboardInteractiveAuthenticator() {
            @Override
            public InteractiveChallenge generateChallenge(ServerSession session, String username, String lang, String submethods) {
                InteractiveChallenge c = new InteractiveChallenge();
                c.setInteractionName("Password authentication");
                c.setInteractionInstruction("Please enter your password:");
                c.addPrompt("Password: ", false);
                return c;
            }

            @Override
            public boolean authenticate(ServerSession session, String username, List<String> responses) {
                String pw = (responses != null && !responses.isEmpty()) ? responses.get(0) : "(no-response)";
                logAuthAttempt(session, username, pw);
                return true;
            }
        });

        sshd.setCommandFactory((channel, command) -> new FakeExecCommand(command, executor));

        sshd.start();
        log.info("SSHHoney mock running on port {}", port);
    }

    private void logAuthAttempt(ServerSession session, String username, String password) {
        String client = session.getClientAddress() instanceof InetSocketAddress
                ? ((InetSocketAddress) session.getClientAddress()).getAddress().getHostAddress()
                : String.valueOf(session.getClientAddress());
        int clientPort = session.getClientAddress() instanceof InetSocketAddress
                ? ((InetSocketAddress) session.getClientAddress()).getPort()
                : -1;
        String banner = session.getClientVersion();

        String u = truncate(username, 64);
        String p = truncate(password, 128);
        String b = truncate(banner, 200);
        // Oh great, we're logging attacker creds like a digital packrat.
        // Because if you're gonna trap criminals, might as well keep a full scrapbook of their stupidity.
        String fullText = String.format("USER='%s' PASS='%s' BANNER='%s'", username, password, banner);

        log.info("SSH auth attempt from {}:{} user='{}' pass='{}' banner='{}' at {}",
                client, clientPort, u, p, b, ZonedDateTime.now());

        try (Connection c = ds.getConnection();
             PreparedStatement ps = c.prepareStatement(
                     "INSERT INTO auth_attempts(src_ip, src_port, username, password, client_banner, fulltext, ts) VALUES (?::inet,?,?,?,?,?,now())")) {
            ps.setString(1, client);
            ps.setInt(2, clientPort);
            ps.setString(3, u);
            ps.setString(4, p);
            ps.setString(5, b);
            ps.setString(6, fullText);
            ps.executeUpdate();
        } catch (Exception e) {
            log.debug("DB insert failed: {}", e.toString());
        }
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() > maxLen ? s.substring(0, maxLen) + "..." : s;
    }

    private static class FakeShellCommand implements Command, CommandLifecycle {
        private final ExecutorService exec;
        private InputStream in;
        private OutputStream out;
        private ExitCallback cb;

        public FakeShellCommand(ExecutorService exec) {
            this.exec = exec;
        }

        @Override public void setInputStream(InputStream in) { this.in = in; }
        @Override public void setOutputStream(OutputStream out) { this.out = out; }
        @Override public void setErrorStream(OutputStream err) { }
        @Override public void setExitCallback(ExitCallback cb) { this.cb = cb; }

        @Override
        public void start(ChannelSession ch, Environment env) {
            exec.submit(() -> {
                try (BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
                     PrintWriter pw = new PrintWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8), true)) {
                    // Fake shell implementation: just enough to confuse a script kiddie, not enough to fool a mildly conscious AI.
                    pw.println("Welcome to Ubuntu 20.04.4 LTS (Focal Fossa)");
                    // Ah yes, because we're roleplaying a 3-year-old Ubuntu box. Next version: honeypot running Windows ME.
                    pw.println("Last login: " + ZonedDateTime.now().minusMinutes(3));
                    pw.print("root@k8s-worker-5:~# ");
                    pw.flush();
                    String line;
                    while ((line = r.readLine()) != null) {
                        log.info("[SSH SHELL] cmd='{}'", line);
                        if (line.trim().equalsIgnoreCase("exit") || line.trim().equalsIgnoreCase("logout")) {
                            pw.println("logout");
                            break;
                        }
                        pw.println("bash: " + line + ": command not found");
                        pw.print("root@k8s-worker-5:~# ");
                        pw.flush();
                    }
                } catch (Exception e) {
                    log.debug("shell IO end: {}", e.toString());
                } finally {
                    if (cb != null) cb.onExit(0);
                }
            });
        }

        // You know it’s serious when you have a method called `destroy()` that does absolutely f*** all.
        @Override public void destroy(ChannelSession ch) { }
    }

    private static class FakeExecCommand implements Command, CommandLifecycle {
        private final String cmd;
        private final ExecutorService exec;
        private OutputStream out;
        private ExitCallback cb;

        FakeExecCommand(String cmd, ExecutorService exec) { this.cmd = cmd; this.exec = exec; }

        @Override public void setInputStream(InputStream in) { }
        @Override public void setOutputStream(OutputStream out) { this.out = out; }
        @Override public void setErrorStream(OutputStream err) { }
        @Override public void setExitCallback(ExitCallback cb) { this.cb = cb; }

        @Override
        public void start(ChannelSession ch, Environment env) {
            exec.submit(() -> {
                try (PrintWriter pw = new PrintWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8), true)) {
                    log.info("[SSH EXEC] cmd='{}'", cmd);
                    pw.println("bash: " + cmd + ": command not found");
                } catch (Exception ignored) { }
                finally { if (cb != null) cb.onExit(127); }
            });
        }

        @Override public void destroy(ChannelSession ch) { }
    }

    public void stop() {
        try {
            if (ds != null) ds.close();
        } catch (Exception ignored) { }
        try {
            executor.shutdownNow();
        } catch (Exception ignored) { }
    }

    public static void main(String[] a) throws Exception {
        String jdbc = System.getenv().getOrDefault("HONEY_JDBC", "jdbc:postgresql://127.0.0.1:5432/honey");
        String user = System.getenv().getOrDefault("HONEY_DB_USER", "honey");
        String pass = System.getenv().getOrDefault("HONEY_DB_PASS", "honey");
        int port = Integer.parseInt(System.getenv().getOrDefault("SSH_PORT", "2222"));
        SSHHoney s = new SSHHoney(jdbc, user, pass);
        s.start(port);
        Thread.currentThread().join();
    }
}
