import re
from pathlib import Path

import yaml

from ldapauth import __version__

ROOT = Path(__file__).parents[1]
APP = ROOT / "ldapauth"


def test_distributed_files_have_no_merge_conflicts():
    markers = re.compile(rb"^(?:<{7} |={7}\r?$|>{7} |\|{7} )", re.MULTILINE)
    files = [ROOT / "README.md", ROOT / "repository.yaml"]
    files.extend(
        path for path in APP.rglob("*") if path.is_file() and "__pycache__" not in path.parts
    )
    files.extend(path for path in (ROOT / ".github").rglob("*") if path.is_file())
    conflicts = [str(path.relative_to(ROOT)) for path in files if markers.search(path.read_bytes())]
    assert not conflicts, f"Unresolved merge conflicts in distributed files: {conflicts}"


def test_single_authoritative_configuration():
    assert not (APP / "config.json").exists()
    config = yaml.safe_load((APP / "config.yaml").read_text())
    assert config["version"] == __version__
    assert set(config["options"]) == set(config["schema"])
    assert config["schema"]["bind_password"] == "password"
    assert config["options"]["bind_password"] == ""
    assert (ROOT / "LICENSE").read_bytes() == (APP / "LICENSE").read_bytes()
    assert (ROOT / "NOTICE").read_bytes() == (APP / "NOTICE").read_bytes()


def test_home_assistant_security_contract():
    config = yaml.safe_load((APP / "config.yaml").read_text())
    assert config["ingress"] is True
    assert config["apparmor"] is True
    assert config["panel_admin"] is True
    assert config["ingress_port"] == 8099
    assert not config.get("host_network", False)
    assert not config.get("ports")
    for key in ("docker_api", "full_access", "host_pid", "hassio_api", "homeassistant_api"):
        assert not config.get(key, False)
    assert not config.get("privileged")
    assert all(item["read_only"] for item in config["map"])
    profile = (APP / "apparmor.txt").read_text()
    assert profile.count("profile ldapauth ") == 1
    assert "complain" not in profile
    assert "\n  file," not in profile
    assert "/data/options.json r," in profile


def test_config_translations_and_s6():
    config = yaml.safe_load((APP / "config.yaml").read_text())
    for language in ("en", "nb"):
        translation = yaml.safe_load(
            (APP / "translations" / f"{language}.yaml").read_text(encoding="utf-8")
        )
        assert set(translation["configuration"]) == set(config["schema"])
    service = APP / "rootfs/etc/s6-overlay/s6-rc.d/ldapauth"
    assert (service / "type").read_text().strip() == "longrun"
    assert (service / "dependencies.d/base").exists()
    assert (APP / "rootfs/etc/s6-overlay/user-bundles.d/user/contents.d/ldapauth").exists()
    run = (service / "run").read_bytes()
    assert b"\r" not in run
    assert b"exec /opt/venv/bin/python -m ldapauth" in run


def test_ingress_paths_are_relative():
    html = (APP / "static/index.html").read_text()
    assert 'src="/' not in html
    assert 'href="/' not in html
    assert "http://" not in html
    assert "https://" not in html
