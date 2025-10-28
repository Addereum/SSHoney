package de.addereum.bagofhoney;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.concurrent.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Command(
        name = "bagofhoney",
        mixinStandardHelpOptions = true,
        version = "bagofhoney 1.0",
        description = "Run SSH/TCP/UDP honeypot services"
)
public class App implements Runnable {
    private static final Logger log = LoggerFactory.getLogger(App.class);
    private static final ExecutorService exec = Executors.newFixedThreadPool(10);

    @Option(names = {"--no-tcp"}, description = "Disable TCP honeypot")
    private boolean disableTcp;

    @Option(names = {"--no-udp"}, description = "Disable UDP honeypot")
    private boolean disableUdp;

    @Option(names = {"--ssh-port"}, description = "SSH honeypot port", defaultValue = "${env:SSH_PORT:-2222}")
    private int sshPort;

    @Option(names = {"--tcp-port"}, description = "TCP honeypot port", defaultValue = "5000")
    private int tcpPort;

    @Option(names = {"--udp-port"}, description = "UDP honeypot port", defaultValue = "4000")
    private int udpPort;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new App()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public void run() {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");

        exec.submit(() -> runSSH(sshPort));

        if (!disableUdp) {
            exec.submit(() -> runUDP(udpPort));
        }

        if (!disableTcp) {
            exec.submit(() -> runTCP(tcpPort));
        }

        try {
            Thread.currentThread().join();
        } catch (InterruptedException ignored) {}
    }

    private static void runSSH(int sshPort) {
        try {
            SSHHoney ssh = new SSHHoney(
                    System.getenv().getOrDefault("HONEY_JDBC", "jdbc:postgresql://db:5432/honey"),
                    System.getenv().getOrDefault("HONEY_DB_USER", "honey"),
                    System.getenv().getOrDefault("HONEY_DB_PASS", "honey")
            );
            log.info("Starting SSH honeypot on port {}", sshPort);
            ssh.start(sshPort);
        } catch (Exception e) {
            log.error("SSH honeypot error", e);
        }
    }

    private static void runUDP(int udpPort) {
        try (DatagramSocket ds = new DatagramSocket(udpPort)) {
            log.info("UDP honeypot listening on {}", udpPort);
            byte[] buf = new byte[4096];
            while (true) {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                ds.receive(p);
                String s = new String(p.getData(), 0, p.getLength(), StandardCharsets.UTF_8);
                log.info("[UDP] {} {}:{} -> {} bytes: {}",
                        ZonedDateTime.now(), p.getAddress(), p.getPort(), p.getLength(), truncate(s, 200));
                byte[] reply = ("OK " + System.currentTimeMillis()).getBytes(StandardCharsets.UTF_8);
                ds.send(new DatagramPacket(reply, reply.length, p.getAddress(), p.getPort()));
            }
        } catch (Exception e) {
            log.error("UDP listener error", e);
        }
    }

    private static void runTCP(int tcpPort) {
        try (ServerSocket ss = new ServerSocket(tcpPort)) {
            log.info("TCP honeypot listening on {}", tcpPort);
            while (true) {
                Socket s = ss.accept();
                exec.submit(() -> handleTCP(s));
            }
        } catch (Exception e) {
            log.error("TCP listener error", e);
        }
    }

    private static void handleTCP(Socket s) {
        try (s) {
            s.setSoTimeout(2000);
            InetAddress addr = s.getInetAddress();
            int port = s.getPort();
            byte[] buf = new byte[4096];
            int read = s.getInputStream().read(buf);
            String payload = read > 0 ? new String(buf, 0, read, StandardCharsets.UTF_8) : "";
            log.info("[TCP] {} {}:{} -> {} bytes: {}",
                    ZonedDateTime.now(), addr, port, read, truncate(payload, 200));
            s.getOutputStream().write("HELLO\n".getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            log.debug("TCP connection error: {}", e.toString());
        }
    }

    private static String truncate(String in, int maxLen) {
        if (in == null) return "";
        return in.length() > maxLen ? in.substring(0, maxLen) + "..." : in;
    }
}