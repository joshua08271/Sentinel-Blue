"""Read-only catalog and disposable-guest prerequisites; never native acceptance."""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import tempfile

CATALOG_ROWS = [{'service_id': 'apache2', 'capability': 'configure', 'unit': 'apache2', 'apt_packages': ['apache2']}, {'service_id': 'bind9', 'capability': 'configure', 'unit': 'named', 'apt_packages': ['bind9', 'bind9-utils']}, {'service_id': 'chrony', 'capability': 'configure', 'unit': 'chronyd', 'apt_packages': ['chrony']}, {'service_id': 'cups', 'capability': 'adopt', 'unit': 'cups', 'apt_packages': ['cups']}, {'service_id': 'dnsmasq', 'capability': 'configure', 'unit': 'dnsmasq', 'apt_packages': ['dnsmasq']}, {'service_id': 'docker', 'capability': 'adopt', 'unit': 'docker', 'apt_packages': ['docker.io']}, {'service_id': 'dovecot', 'capability': 'configure', 'unit': 'dovecot', 'apt_packages': ['dovecot-imapd', 'dovecot-pop3d']}, {'service_id': 'exim4', 'capability': 'adopt', 'unit': 'exim4', 'apt_packages': ['exim4']}, {'service_id': 'freeradius', 'capability': 'adopt', 'unit': 'freeradius', 'apt_packages': ['freeradius']}, {'service_id': 'gunicorn', 'capability': 'configure', 'unit': 'sentinel-gunicorn', 'apt_packages': []}, {'service_id': 'haproxy', 'capability': 'configure', 'unit': 'haproxy', 'apt_packages': ['haproxy']}, {'service_id': 'isc-dhcp-server', 'capability': 'configure', 'unit': 'isc-dhcp-server', 'apt_packages': ['isc-dhcp-server']}, {'service_id': 'kea-dhcp4', 'capability': 'adopt', 'unit': 'kea-dhcp4-server', 'apt_packages': ['kea-dhcp4-server']}, {'service_id': 'krb5-kdc', 'capability': 'adopt', 'unit': 'krb5-kdc', 'apt_packages': ['krb5-kdc']}, {'service_id': 'mariadb', 'capability': 'configure', 'unit': 'mariadb', 'apt_packages': ['mariadb-server']}, {'service_id': 'memcached', 'capability': 'adopt', 'unit': 'memcached', 'apt_packages': ['memcached']}, {'service_id': 'mongodb', 'capability': 'adopt', 'unit': 'mongod', 'apt_packages': ['mongodb-server']}, {'service_id': 'mosquitto', 'capability': 'configure', 'unit': 'mosquitto', 'apt_packages': ['mosquitto']}, {'service_id': 'nfs-server', 'capability': 'configure', 'unit': 'nfs-server', 'apt_packages': ['nfs-kernel-server']}, {'service_id': 'nginx', 'capability': 'configure', 'unit': 'nginx', 'apt_packages': ['nginx']}, {'service_id': 'ntpd', 'capability': 'adopt', 'unit': 'ntpsec', 'apt_packages': ['ntpsec']}, {'service_id': 'openssh-server', 'capability': 'configure', 'unit': 'ssh', 'apt_packages': ['openssh-server']}, {'service_id': 'php-fpm', 'capability': 'adopt', 'unit': 'php-fpm', 'apt_packages': ['php-fpm']}, {'service_id': 'podman', 'capability': 'adopt', 'unit': 'podman', 'apt_packages': ['podman']}, {'service_id': 'postfix', 'capability': 'configure', 'unit': 'postfix', 'apt_packages': ['postfix']}, {'service_id': 'postgresql', 'capability': 'configure', 'unit': 'postgresql', 'apt_packages': ['postgresql']}, {'service_id': 'proftpd', 'capability': 'adopt', 'unit': 'proftpd', 'apt_packages': ['proftpd-core']}, {'service_id': 'rabbitmq-server', 'capability': 'adopt', 'unit': 'rabbitmq-server', 'apt_packages': ['rabbitmq-server']}, {'service_id': 'redis', 'capability': 'configure', 'unit': 'redis-server', 'apt_packages': ['redis-server']}, {'service_id': 'rsyslog', 'capability': 'configure', 'unit': 'rsyslog', 'apt_packages': ['rsyslog']}, {'service_id': 'samba', 'capability': 'configure', 'unit': 'smbd', 'apt_packages': ['samba']}, {'service_id': 'slapd', 'capability': 'adopt', 'unit': 'slapd', 'apt_packages': ['slapd', 'ldap-utils']}, {'service_id': 'squid', 'capability': 'adopt', 'unit': 'squid', 'apt_packages': ['squid']}, {'service_id': 'sssd', 'capability': 'adopt', 'unit': 'sssd', 'apt_packages': ['sssd']}, {'service_id': 'systemd-timesyncd', 'capability': 'adopt', 'unit': 'systemd-timesyncd', 'apt_packages': []}, {'service_id': 'tftpd-hpa', 'capability': 'adopt', 'unit': 'tftpd-hpa', 'apt_packages': ['tftpd-hpa']}, {'service_id': 'tomcat', 'capability': 'adopt', 'unit': 'tomcat9', 'apt_packages': ['tomcat9']}, {'service_id': 'unbound', 'capability': 'configure', 'unit': 'unbound', 'apt_packages': ['unbound']}, {'service_id': 'vsftpd', 'capability': 'configure', 'unit': 'vsftpd', 'apt_packages': ['vsftpd']}]
RUNTIME_SHA256 = "9e3a7d254d4866be393eac5649211e656446ae1c16651ee0d4f64933a33d3ab5"
LIMIT = 64 * 1024


def query(argv):
    """Only the literal status/version queries assembled by main are admitted."""
    if not Path(argv[0]).is_file():
        return {"status": "executable_missing", "returncode": None, "stdout": "", "stderr": ""}
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out,
                                       stderr=err, start_new_session=True)
        except OSError as exc:
            return {"status": "execution_error", "returncode": None,
                    "stdout": "", "stderr": type(exc).__name__}
        try:
            code = process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            return {"status": "timeout", "returncode": None, "stdout": "", "stderr": ""}
        out.seek(0)
        err.seek(0)
        stdout, stderr = out.read(LIMIT + 1), err.read(LIMIT + 1)
    if len(stdout) > LIMIT or len(stderr) > LIMIT:
        return {"status": "output_limit", "returncode": code, "stdout": "", "stderr": ""}
    return {"status": "observed", "returncode": code,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace")}


def main():
    packages = sorted({p for row in CATALOG_ROWS for p in row["apt_packages"]})
    units = sorted({row["unit"] + ".service" for row in CATALOG_ROWS})
    filesystem = os.statvfs("/")
    kvm = Path("/dev/kvm")
    kvm_character_device = False
    try:
        kvm_character_device = stat.S_ISCHR(kvm.stat().st_mode)
    except OSError:
        pass
    result = {
        "schema": 1,
        "mode": "read-only-preflight",
        "native_acceptances": 0,
        "settings_changed_by_helper": False,
        "catalog_runtime_sha256": RUNTIME_SHA256,
        "catalog": CATALOG_ROWS,
        "platform": platform.machine(),
        "effective_uid": os.geteuid(),
        "sessions": query(["/usr/bin/who"]),
        "root_filesystem_available_bytes": filesystem.f_bavail * filesystem.f_frsize,
        "memory": query(["/usr/bin/free", "-m"]),
        "kvm_character_device": kvm_character_device,
        "kvm_current_user_read_write": kvm_character_device and os.access(kvm, os.R_OK | os.W_OK),
        "qemu_version": query(["/usr/bin/qemu-system-x86_64", "--version"]),
        "qemu_img_version": query(["/usr/bin/qemu-img", "--version"]),
        "package_status": query(["/usr/bin/dpkg-query", "--show",
                                 "--showformat=${Package}\\t${Version}\\t${db:Status-Status}\\n", *packages]),
        "unit_status": query(["/usr/bin/systemctl", "show", "--no-pager",
                              "--property=Id,LoadState,ActiveState,SubState,UnitFileState", "--", *units]),
        "scope": "No installs, service validators, service mutations, network probes, or guest launches. Missing products do not count as tested. Results stay private. Temporary capture files are closed and removed.",
    }
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
