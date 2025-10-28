package de.addereum.bagofhoney;

import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.concurrent.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class App {
    private static final Logger log = LoggerFactory.getLogger(App.class);

    // fester Threadpool statt unendlicher Threads
    private static final ExecutorService exec = Executors.newFixedThreadPool(10);

    public static void main(String[] args) throws Exception {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");

        int udpPort = 4000;
        int tcpPort = 5000;
        int sshPort = Integer.parseInt(System.getenv().getOrDefault("SSH_PORT", "2222"));

        // SSH
        exec.submit(() -> runSSH(sshPort));

        // UDP
        exec.submit(() -> runUDP(udpPort));

        // TCP
        exec.submit(() -> runTCP(tcpPort));

        Thread.currentThread().join();
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
                        ZonedDateTime.now(), p.getAddress(), p.getPort(), p.getLength(), safe(s));
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
                    ZonedDateTime.now(), addr, port, read, safe(payload));
            s.getOutputStream().write("HELLO\n".getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            log.debug("TCP connection error: {}", e.toString());
        }
    }

    private static String safe(String in) {
        if (in == null) return "";
        String s = in.replaceAll("[\\r\\n\\x00\\p{Cntrl}]", "?");
        return s.length() > 200 ? s.substring(0, 200) + "..." : s;
    }
}
