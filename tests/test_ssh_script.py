"""node_agent/ssh-password-internal.sh against a scratch sshd (real `sshd -T`, no root, no reload)."""
import getpass
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "node_agent" / "ssh-password-internal.sh"
SSHD = shutil.which("sshd") or "/usr/sbin/sshd"


@unittest.skipUnless(os.path.exists(SSHD) and shutil.which("ssh-keygen"), "sshd/ssh-keygen not installed")
class SshPasswordScript(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sm-sshd-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / "conf.d").mkdir()
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.tmp / "hostkey")], check=True)
        self.cfg = self.tmp / "sshd_config"
        self.cfg.write_text(f"Include {self.tmp}/conf.d/*.conf\nHostKey {self.tmp}/hostkey\n"
                            "PubkeyAuthentication yes\nKbdInteractiveAuthentication no\n")
        (self.tmp / "conf.d" / "50-cloud-init.conf").write_text("PasswordAuthentication yes\n")  # what Ubuntu cloud images ship
        self.original = self.cfg.read_text()
        self.drop = self.tmp / "conf.d" / "10-sm-password-internal.conf"

    def run_script(self, *args):
        env = {**os.environ, "SM_TEST": "1", "SSHD_CONFIG": str(self.cfg), "SSHD_DROPIN": str(self.drop),
               "SUDO_USER": getpass.getuser()}
        return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=env)

    def setting(self, key, addr):
        out = subprocess.run([SSHD, "-f", str(self.cfg), "-T", "-C", f"user={getpass.getuser()},host=t,addr={addr}"],
                             capture_output=True, text=True).stdout
        return next(l.split()[1] for l in out.splitlines() if l.startswith(key + " "))

    def test_internet_needs_a_key_but_lan_and_tailscale_keep_passwords(self):
        self.assertEqual(self.setting("passwordauthentication", "8.8.8.8"), "yes", "precondition: passwords open everywhere")
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)  # the old '/' in the sed marker made this fail
        for addr, want in (("8.8.8.8", "no"), ("2001:4860::1", "no"), ("192.168.1.5", "yes"), ("10.0.0.2", "yes"),
                           ("100.94.77.73", "yes"), ("fd7a:115c:a1e0::1", "yes"), ("127.0.0.1", "yes")):
            self.assertEqual(self.setting("passwordauthentication", addr), want, addr)
        self.assertEqual(self.setting("pubkeyauthentication", "8.8.8.8"), "yes", "keys still work from anywhere")
        self.assertEqual(self.cfg.read_text().count("# >>> sm:"), 1)

    def test_running_twice_does_not_stack_blocks_and_undo_restores_everything(self):
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.cfg.read_text().count("# >>> sm:"), 1)
        r = self.run_script("--undo")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(self.drop.exists())
        self.assertEqual(self.cfg.read_text(), self.original)
        self.assertEqual(self.setting("passwordauthentication", "8.8.8.8"), "yes")

    def test_failed_verification_rolls_everything_back(self):
        # an earlier `Match all` wins over our block, so the internet would keep passwords: the check must catch it
        self.cfg.write_text(self.original + "Match all\n    PasswordAuthentication yes\n")
        before = self.cfg.read_text()
        r = self.run_script()
        self.assertEqual(r.returncode, 1)
        self.assertIn("되돌렸습니다", r.stdout)
        self.assertFalse(self.drop.exists())
        self.assertEqual(self.cfg.read_text(), before)

    @unittest.skipIf(os.geteuid() == 0, "root ignores directory permissions")
    def test_unexpected_error_rolls_back_too(self):
        (self.tmp / "conf.d").chmod(0o555)  # writing the drop-in now fails mid-script
        self.addCleanup((self.tmp / "conf.d").chmod, 0o755)
        r = self.run_script()
        self.assertEqual(r.returncode, 1)
        self.assertIn("예상치 못한 오류", r.stdout)
        self.assertEqual(self.cfg.read_text(), self.original)

    def test_refuses_when_key_login_is_off(self):
        self.cfg.write_text(self.original.replace("PubkeyAuthentication yes", "PubkeyAuthentication no"))
        before = self.cfg.read_text()
        r = self.run_script()
        self.assertEqual(r.returncode, 1)
        self.assertIn("키 로그인이 꺼져 있어", r.stdout)
        self.assertEqual(self.cfg.read_text(), before)


if __name__ == "__main__":
    unittest.main()
