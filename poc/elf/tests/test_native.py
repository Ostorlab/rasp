"""Black-box checks for the native runtime, independent of ELF rewriting."""

import contextlib
import ctypes
import datetime
import hashlib
import http.server as http_server
import ipaddress
import os
import pathlib
import ssl
import subprocess
import tempfile
import threading
import time
import typing
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = pathlib.Path(__file__).resolve().parents[1]


class NativeRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = pathlib.Path(self.tmp.name)
        self.publisher = ed25519.Ed25519PrivateKey.generate()
        self.client = ed25519.Ed25519PrivateKey.generate()
        public = (
            self.publisher.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        )
        private = self.client.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        ).hex()
        (self.directory / "rasp_build.h").write_text(
            f'#define RASP_PUBLISHER_PUBLIC_HEX "{public}"\n#define RASP_CLIENT_PRIVATE_HEX "{private}"\n'
        )
        source = ROOT / "runtime" / "rasp_runtime.c"
        self.assertTrue(source.exists(), "Native protection runtime has not been implemented")
        subprocess.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-O2",
                "-fvisibility=hidden",
                "-pthread",
                "-I",
                str(self.directory),
                str(source),
                "-o",
                str(self.directory / "librasp_runtime.so"),
                "-lcrypto",
                "-lssl",
                "-ldl",
            ],
            check=True,
        )
        (self.directory / "sample.c").write_text("""#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <pthread.h>
static void *short_worker(void *unused) { (void)unused; return NULL; }
static void *churn_workers(void *unused) { (void)unused; for(int i=0;i<1000;i++) { pthread_t thread; if(pthread_create(&thread,NULL,short_worker,NULL)==0) pthread_join(thread,NULL); } return NULL; }
static void *worker(void *unused) { (void)unused; printf("worker=%ld\\n",syscall(SYS_gettid)); fflush(stdout); sleep(3); return NULL; }
int main(int argc,char **argv) {
 if(argc>1 && !strcmp(argv[1],"churn")) { pthread_t thread; pthread_create(&thread,NULL,churn_workers,NULL); int (*check)(const void *,size_t)=dlsym(RTLD_DEFAULT,"rasp_checkpoint"); for(int i=0;i<200;i++) { if(check("payment",7)) return 31; usleep(500); } pthread_join(thread,NULL); return 7; }
 if(argc>1 && !strcmp(argv[1],"worker")) { pthread_t thread; pthread_create(&thread,NULL,worker,NULL); sleep(1); int (*check)(const void *,size_t)=dlsym(RTLD_DEFAULT,"rasp_checkpoint"); int result=check("payment",7); printf("checkpoint=%d\\n",result); fflush(stdout); pthread_join(thread,NULL); return result==0?7:31; }
 if(argc>1 && !strcmp(argv[1],"wait")) { puts("started"); fflush(stdout); sleep(2); }
 if(argc>1 && !strcmp(argv[1],"checkpoint")) { int (*check)(const void *,size_t)=dlsym(RTLD_DEFAULT,"rasp_checkpoint"); if(!check || check("payment",7)) return 31; }
 if(argc>1 && !strcmp(argv[1],"fork")) { pid_t child=fork(); if(child==0) { int (*check)(const void *,size_t)=dlsym(RTLD_DEFAULT,"rasp_checkpoint"); _exit(check && check("payment",7)==-1 ? 32:33); } int status=0; waitpid(child,&status,0); return WEXITSTATUS(status); }
 if(argc>1 && !strncmp(argv[1],"prepare",7)) {
  int (*prepare)(const void *,size_t,char *,size_t)=dlsym(RTLD_DEFAULT,"rasp_prepare_request");
  if(!prepare) return 41;
  char evidence[8192];
  if(!strcmp(argv[1],"prepareinvalid")) { if(prepare(NULL,7,evidence,sizeof(evidence))!=-1 || prepare("payment",7,NULL,sizeof(evidence))!=-1 || prepare("payment",7,evidence,8)!=-1) return 42; return 0; }
  if(!strcmp(argv[1],"preparefork")) { pid_t child=fork(); if(child==0) _exit(prepare("payment",7,evidence,sizeof(evidence))==-1?32:33); int status=0; waitpid(child,&status,0); return WEXITSTATUS(status); }
  if(!strcmp(argv[1],"preparewait")) { puts("started"); fflush(stdout); sleep(1); }
  int length=!strcmp(argv[1],"prepareempty")?prepare(NULL,0,evidence,sizeof(evidence)):prepare("payment",7,evidence,sizeof(evidence));
  if(length<0) return 40;
  if(evidence[length]!='\\0') return 43;
  fwrite(evidence,1,(size_t)length,stdout); return 0;
 }
 if(argc>1 && !strcmp(argv[1],"connectstorage")) { int fd=socket(AF_INET,SOCK_STREAM,0); struct sockaddr_storage address={0}; struct sockaddr_in *ipv4=(struct sockaddr_in *)&address; ipv4->sin_family=AF_INET; ipv4->sin_port=htons(9); inet_pton(AF_INET,"127.0.0.1",&ipv4->sin_addr); connect(fd,(const struct sockaddr *)&address,sizeof(address)); close(fd); }
 if(argc>1 && !strcmp(argv[1],"connect")) { int fd=socket(AF_INET,SOCK_STREAM,0); struct sockaddr_in address={0}; address.sin_family=AF_INET; address.sin_port=htons(9); inet_pton(AF_INET,"127.0.0.1",&address.sin_addr); connect(fd,(const struct sockaddr *)&address,sizeof(address)); close(fd); }
 printf("original:%s\\n",argc>1?argv[1]:"none"); return 7;
}
""")
        subprocess.run(
            [
                "gcc",
                str(self.directory / "sample.c"),
                "-pthread",
                "-L",
                str(self.directory),
                "-Wl,--no-as-needed",
                "-lrasp_runtime",
                "-Wl,-rpath,$ORIGIN",
                "-ldl",
                "-o",
                str(self.directory / "sample"),
            ],
            check=True,
        )
        self.manifest()

    def manifest(self, interval: str = "100", endpoint: str = "", server: str = "0" * 64) -> None:
        def digest(name: str) -> str:
            return hashlib.sha256((self.directory / name).read_bytes()).hexdigest()

        client = self.client.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        body = f"v=rasp-elf-manifest-1\nbuild={'a' * 64}\nexe={digest('sample')}\nruntime={digest('librasp_runtime.so')}\nendpoint={endpoint}\ninterval_ms={interval}\nclient_public={client}\nserver_public={server}\n".encode()
        (self.directory / "rasp.manifest").write_bytes(
            body + b"signature=" + self.publisher.sign(body).hex().encode() + b"\n"
        )

    @staticmethod
    def stop_process(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            process.kill()

    def run_sample(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [str(self.directory / "sample"), *args], capture_output=True, env=env, check=False, timeout=8
        )

    def testNativeRuntime_whenOffline_preservesApplicationBehavior(self) -> None:
        result = self.run_sample("argument")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(result.stdout, b"original:argument\n")

    def testNativeRuntime_whenOfflineCheckpoint_returnsAllow(self) -> None:
        result = self.run_sample("checkpoint")
        self.assertEqual(result.returncode, 7, result.stderr)

    def testNativeRuntime_whenManifestMissing_blocksBeforeMain(self) -> None:
        (self.directory / "rasp.manifest").unlink()
        result = self.run_sample()
        self.assertEqual(result.returncode, 173)
        self.assertEqual(result.stdout, b"")

    def testNativeRuntime_withInvalidSignedInterval_blocksBeforeMain(self) -> None:
        for interval in ("0", "99", "60001", "-100", "100junk"):
            with self.subTest(interval=interval):
                self.manifest(interval=interval)
                self.assertEqual(self.run_sample().returncode, 173)

    def testNativeRuntime_whenExecutableAltered_detectsTampering(self) -> None:
        with (self.directory / "sample").open("ab") as binary:
            binary.write(b"tampered")
        result = self.run_sample()
        self.assertEqual(result.returncode, 173)
        self.assertIn(b"tamper", result.stderr)

    def testNativeRuntime_withPreloadEnvironment_blocksStartup(self) -> None:
        env = dict(os.environ, LD_PRELOAD="/nonexistent/instrumentation.so")
        result = self.run_sample(env=env)
        self.assertEqual(result.returncode, 173)
        self.assertIn(b"preload", result.stderr)

    def testNativeRuntime_whenLibraryAlteredAfterStartup_monitorBlocks(self) -> None:
        process = subprocess.Popen(
            [str(self.directory / "sample"), "wait"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.addCleanup(self.stop_process, process)
        self.assertEqual(process.stdout.readline(), b"started\n")
        with (self.directory / "librasp_runtime.so").open("ab") as binary:
            binary.write(b"tampered")
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 173, stderr)
        self.assertIn(b"tamper", stderr)
        self.assertNotIn(b"original", stdout)

    def backend(
        self, mode: str = "allow", tls: bool = False, certificate_ip: str = "127.0.0.1", interval: str = "60000"
    ) -> list[dict[str, str]]:
        server_key = ed25519.Ed25519PrivateKey.generate()
        records: list[dict[str, str]] = []
        client_public = self.client.public_key()

        class Handler(http_server.BaseHTTPRequestHandler):
            def log_message(self, format_string: str, *args: typing.Any) -> None:
                pass

            def do_POST(handler: http_server.BaseHTTPRequestHandler) -> None:
                body = handler.rfile.read(int(handler.headers["Content-Length"]))
                if mode == "hang":
                    time.sleep(3)
                    return
                if handler.path == "/v1/challenge":
                    response = b"nonce=" + os.urandom(32).hex().encode() + b"\n"
                else:
                    signed, signature = body.rsplit(b"signature=", 1)
                    client_public.verify(bytes.fromhex(signature.decode().strip()), signed)
                    fields = dict(line.split("=", 1) for line in signed.decode().splitlines())
                    records.append(fields)
                    action = mode if mode in ("deny", "step_up") else "allow"
                    if mode == fields["operation"] + "_deny":
                        action = "deny"
                    evidence = hashlib.sha256(signed).hexdigest()
                    nonce = fields["nonce"]
                    build = fields["build"]
                    expires = int(time.time()) + 30
                    if mode == "wrong_hash":
                        evidence = "0" * 64
                    if mode == "wrong_nonce":
                        nonce = "0" * 64
                    if mode == "wrong_build":
                        build = "0" * 64
                    if mode == "expired":
                        expires = int(time.time()) - 1
                    if mode == "future":
                        expires = int(time.time()) + 90
                    response = f"v=rasp-elf-decision-1\nbuild={build}\nnonce={nonce}\nevidence={evidence}\naction={action}\nexpires={expires}\n".encode()
                    signature = server_key.sign(response)
                    if mode == "bad_signature":
                        signature = b"\x00" * 64
                    response += b"signature=" + signature.hex().encode() + b"\n"
                handler.send_response(503 if mode == "bad_status" else 200)
                if mode != "no_length":
                    handler.send_header("Content-Length", str(20000 if mode == "oversized" else len(response)))
                if mode == "duplicate_length":
                    handler.send_header("Content-Length", str(len(response)))
                if mode == "chunked":
                    handler.send_header("Transfer-Encoding", "chunked")
                handler.end_headers()
                if mode == "truncated":
                    response = response[:-5]
                if mode == "nul":
                    response = response.replace(b"nonce", b"non\x00e")
                if mode == "trickle" and handler.path == "/v1/challenge":
                    for offset in range(0, len(response), 10):
                        try:
                            handler.wfile.write(response[offset : offset + 10])
                        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                            return
                        time.sleep(0.45)
                    return
                handler.wfile.write(response)

        server = http_server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        if tls is True:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Native runtime test")])
            now = datetime.datetime.now(datetime.timezone.utc)
            certificate = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(
                    x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(certificate_ip))]), critical=False
                )
                .sign(key, hashes.SHA256())
            )
            cert_path = self.directory / "test-cert.pem"
            key_path = self.directory / "test-key.pem"
            cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                )
            )
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path, key_path)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        public = server_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.manifest(
            interval=interval,
            endpoint=f"{'https' if tls is True else 'http'}://127.0.0.1:{server.server_port}",
            server=public,
        )
        return records

    def testNativeRuntime_withSignedBackendAllow_bindsCheckpointPayload(self) -> None:
        records = self.backend()
        result = self.run_sample("checkpoint")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual([entry["operation"] for entry in records], ["startup", "checkpoint"])
        self.assertEqual(records[0]["request"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(records[1]["request"], hashlib.sha256(b"payment").hexdigest())

    def testNativeRuntime_whenBusinessConnectRequested_getsFreshAuthorization(self) -> None:
        records = self.backend()
        result = self.run_sample("connect")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual([entry["operation"] for entry in records], ["startup", "connect"])
        self.assertNotEqual(records[1]["request"], hashlib.sha256(b"").hexdigest())

    def testNativeRuntime_withDeniedOrInvalidBackendDecision_blocksMain(self) -> None:
        for mode in (
            "deny",
            "step_up",
            "wrong_hash",
            "wrong_nonce",
            "wrong_build",
            "expired",
            "future",
            "bad_signature",
        ):
            with self.subTest(mode=mode):
                self.backend(mode)
                result = self.run_sample()
                self.assertEqual(result.returncode, 173, result.stderr)
                self.assertEqual(result.stdout, b"")

    def testNativeRuntime_withNonLoopbackHttpEndpoint_rejectsManifest(self) -> None:
        self.manifest(endpoint="http://192.0.2.1:80")
        result = self.run_sample()
        self.assertEqual(result.returncode, 173)
        self.assertIn(b"invalidManifest", result.stderr)

    def testNativeRuntime_withInvalidSignedBackendConfiguration_rejectsBeforeTransport(self) -> None:
        for endpoint in ("https://bad_host:443", "https://127.0.0.1:1"):
            with self.subTest(endpoint=endpoint):
                self.manifest(endpoint=endpoint)
                result = self.run_sample()
                self.assertEqual(result.returncode, 173)
                self.assertIn(b"invalidManifest", result.stderr)

    def testNativeRuntime_withMalformedHttpResponse_failsClosed(self) -> None:
        for mode in ("bad_status", "no_length", "duplicate_length", "oversized", "truncated", "chunked", "nul"):
            with self.subTest(mode=mode):
                self.backend(mode)
                result = self.run_sample()
                self.assertEqual(result.returncode, 173, result.stderr)
                self.assertEqual(result.stdout, b"")

    def testNativeRuntime_withHttps_verifiesTrustAndHostname(self) -> None:
        self.backend(tls=True)
        untrusted = self.run_sample()
        self.assertEqual(untrusted.returncode, 173, untrusted.stderr)
        env = dict(os.environ, SSL_CERT_FILE=str(self.directory / "test-cert.pem"))
        trusted = self.run_sample(env=env)
        self.assertEqual(trusted.returncode, 7, trusted.stderr)
        self.backend(tls=True, certificate_ip="192.0.2.1")
        mismatched = self.run_sample(env=env)
        self.assertEqual(mismatched.returncode, 173, mismatched.stderr)

    def testNativeRuntime_withManifestFifo_rejectsWithoutBlocking(self) -> None:
        manifest = self.directory / "rasp.manifest"
        manifest.unlink()
        os.mkfifo(manifest)
        started = time.monotonic()
        result = self.run_sample()
        self.assertEqual(result.returncode, 173)
        self.assertLess(time.monotonic() - started, 2)

    def testNativeRuntime_whenLibraryReplacedByFifo_monitorBlocks(self) -> None:
        process = subprocess.Popen(
            [str(self.directory / "sample"), "wait"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.addCleanup(self.stop_process, process)
        self.assertEqual(process.stdout.readline(), b"started\n")
        runtime = self.directory / "librasp_runtime.so"
        runtime.unlink()
        os.mkfifo(runtime)
        _, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 173, stderr)

    def testNativeRuntime_whenRuntimeExpandedToSparseFile_rejectsWithoutLongHashing(self) -> None:
        process = subprocess.Popen(
            [str(self.directory / "sample"), "wait"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.addCleanup(self.stop_process, process)
        self.assertEqual(process.stdout.readline(), b"started\n")
        started = time.monotonic()
        with (self.directory / "librasp_runtime.so").open("r+b") as runtime:
            runtime.truncate(8 * 1024 * 1024 * 1024)
        _, stderr = process.communicate(timeout=3)
        self.assertEqual(process.returncode, 173, stderr)
        self.assertLess(time.monotonic() - started, 1)

    def testNativeRuntime_whenBackendHangs_rejectsWithinTimeout(self) -> None:
        self.backend("hang")
        started = time.monotonic()
        result = self.run_sample()
        self.assertEqual(result.returncode, 173, result.stderr)
        self.assertLess(time.monotonic() - started, 2.8)

    def testNativeRuntime_whenBackendTricklesResponse_rejectsWithinAbsoluteDeadline(self) -> None:
        for tls in (False, True):
            with self.subTest(tls=tls):
                self.backend("trickle", tls=tls)
                env = dict(os.environ, SSL_CERT_FILE=str(self.directory / "test-cert.pem")) if tls is True else None
                started = time.monotonic()
                result = self.run_sample(env=env)
                self.assertEqual(result.returncode, 173, result.stderr)
                self.assertLess(time.monotonic() - started, 2.8)

    def testNativeRuntime_whenBackendDeniesMonitor_blocksRunningApplication(self) -> None:
        records = self.backend("monitor_deny", interval="100")
        result = self.run_sample("wait")
        self.assertEqual(result.returncode, 173, result.stderr)
        self.assertEqual(result.stdout, b"started\n")
        self.assertEqual([entry["operation"] for entry in records], ["startup", "monitor"])

    def testNativeRuntime_whenBackendDeniesConnect_blocksBusinessCall(self) -> None:
        records = self.backend("connect_deny")
        result = self.run_sample("connect")
        self.assertEqual(result.returncode, 173, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual([entry["operation"] for entry in records], ["startup", "connect"])

    def testNativeRuntime_whenBackendDeniesCheckpoint_returnsFailure(self) -> None:
        self.backend("checkpoint_deny")
        result = self.run_sample("checkpoint")
        self.assertEqual(result.returncode, 31, result.stderr)

    def testNativeRuntime_whenForkedCheckpointCalled_rejectsWithoutInheritedLock(self) -> None:
        result = self.run_sample("fork")
        self.assertEqual(result.returncode, 32, result.stderr)

    @staticmethod
    def trace_worker(thread_id: int, attach: bool) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.ptrace.argtypes = (ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p)
        libc.ptrace.restype = ctypes.c_long
        operation = 16 if attach is True else 17
        result = libc.ptrace(operation, thread_id, None, None)
        if result != 0:
            code = ctypes.get_errno()
            if attach is False and code == 3:
                # A ptrace-stopped worker killed by exit_group can leave an
                # exit event for the tracer, delaying the leader's reaping.
                with contextlib.suppress(ChildProcessError):
                    os.waitpid(thread_id, 0x40000000)
                return
            raise OSError(code, "ptrace worker")
        if attach is True:
            os.waitpid(thread_id, os.WUNTRACED | 0x40000000)

    def testNativeRuntime_whenThreadsExitDuringScanning_allowsCleanProcess(self) -> None:
        result = self.run_sample("churn")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertNotIn(b"detectorFailure", result.stderr)

    def testNativeRuntime_whenDebuggerAttachedToWorker_monitorBlocks(self) -> None:
        process = subprocess.Popen(
            [str(self.directory / "sample"), "worker"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.addCleanup(self.stop_process, process)
        thread_id = int(process.stdout.readline().decode().split("=", 1)[1])
        self.trace_worker(thread_id, True)
        try:
            time.sleep(0.5)
        finally:
            self.trace_worker(thread_id, False)
        _, stderr = process.communicate(timeout=4)
        self.assertEqual(process.returncode, 173, stderr)
        self.assertIn(b"debugger", stderr)

    def testNativeRuntime_whenDebuggerAttachedToWorker_checkpointReturnsFailure(self) -> None:
        self.manifest(interval="60000")
        process = subprocess.Popen(
            [str(self.directory / "sample"), "worker"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.addCleanup(self.stop_process, process)
        thread_id = int(process.stdout.readline().decode().split("=", 1)[1])
        self.trace_worker(thread_id, True)
        try:
            checkpoint = process.stdout.readline()
        finally:
            self.trace_worker(thread_id, False)
        _, stderr = process.communicate(timeout=4)
        self.assertEqual(checkpoint, b"checkpoint=-1\n", stderr)
        self.assertEqual(process.returncode, 31, stderr)
        self.assertIn(b"debugger", stderr)

    def testNativeRuntime_whenRequestPrepared_exportsSignedPayloadWithoutConsumingChallenge(self) -> None:
        records = self.backend()
        result = self.run_sample("prepare")
        self.assertEqual(result.returncode, 0, result.stderr)
        signed, signature = result.stdout.rsplit(b"signature=", 1)
        self.client.public_key().verify(bytes.fromhex(signature.decode().strip()), signed)
        fields = dict(line.split("=", 1) for line in signed.decode().splitlines())
        self.assertEqual(fields["operation"], "checkpoint")
        self.assertEqual(fields["request"], hashlib.sha256(b"payment").hexdigest())
        self.assertEqual(fields["threats"], "none")
        self.assertEqual(fields["build"], "a" * 64)
        self.assertEqual([entry["operation"] for entry in records], ["startup"])
        self.assertNotEqual(fields["nonce"], records[0]["nonce"])

    def testNativeRuntime_whenEmptyRequestPrepared_exportsEmptyPayloadHash(self) -> None:
        self.backend()
        result = self.run_sample("prepareempty")
        self.assertEqual(result.returncode, 0, result.stderr)
        fields = dict(line.split("=", 1) for line in result.stdout.decode().splitlines())
        self.assertEqual(fields["request"], hashlib.sha256(b"").hexdigest())

    def testNativeRuntime_whenPrepareRequestOffline_returnsFailure(self) -> None:
        result = self.run_sample("prepare")
        self.assertEqual(result.returncode, 40, result.stderr)

    def testNativeRuntime_whenPrepareRequestInputsInvalid_returnsFailure(self) -> None:
        records = self.backend()
        result = self.run_sample("prepareinvalid")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([entry["operation"] for entry in records], ["startup"])

    def testNativeRuntime_whenForkedRequestPrepared_returnsFailure(self) -> None:
        self.backend()
        result = self.run_sample("preparefork")
        self.assertEqual(result.returncode, 32, result.stderr)

    def testNativeRuntime_whenTamperedRequestPrepared_returnsFailure(self) -> None:
        records = self.backend()
        process = subprocess.Popen(
            [str(self.directory / "sample"), "preparewait"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.addCleanup(self.stop_process, process)
        self.assertEqual(process.stdout.readline(), b"started\n")
        with (self.directory / "librasp_runtime.so").open("ab") as runtime:
            runtime.write(b"tampered")
        _, stderr = process.communicate(timeout=3)
        self.assertEqual(process.returncode, 40, stderr)
        self.assertIn(b"tamper", stderr)
        self.assertEqual([entry["operation"] for entry in records], ["startup"])

    def testNativeRuntime_withSockaddrStorage_authorizesExactProvidedBytes(self) -> None:
        records = self.backend()
        result = self.run_sample("connectstorage")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual([entry["operation"] for entry in records], ["startup", "connect"])


if __name__ == "__main__":
    unittest.main()
