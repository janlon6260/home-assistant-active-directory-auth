import argparse
import asyncio
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from playwright.async_api import async_playwright

from ldapauth import server
from ldapauth.server import Runtime, create_ingress_app
from ldapauth.settings import Settings


def test_ca() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Example AD Root CA")])
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )


async def main(chrome: bool):
    with tempfile.TemporaryDirectory() as temporary:
        settings = Settings(
            ldap_server="ldaps://dc.example.com:636",
            bind_user="test@example.com",
            bind_password="synthetic",
            user_base_dn="OU=Users,DC=example,DC=com",
            groups_base_dn="OU=Groups,DC=example,DC=com",
            user_group="HA-Users",
            admin_group="HA-Administrators",
        )
        runtime = Runtime(settings, Path(temporary), directory=Mock(), legacy_paths=())

        original_peer = server.peer_address
        server.peer_address = lambda request: server.SUPERVISOR_IP
        app = web.Application()
        prefix = "/api/hassio_ingress/test-session"
        app.add_subapp(prefix, create_ingress_app(runtime))
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        output = Path("test-results")
        await asyncio.to_thread(output.mkdir, exist_ok=True)
        try:
            async with async_playwright() as playwright:
                launch = {"channel": "chrome"} if chrome else {}
                browser = await playwright.chromium.launch(headless=True, **launch)
                try:
                    page = await browser.new_page(
                        viewport={"width": 1440, "height": 1100},
                        locale="en-GB",
                        color_scheme="light",
                    )
                    errors, bad_responses = [], []
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    page.on(
                        "response",
                        lambda response: (
                            bad_responses.append(response.url) if response.status >= 400 else None
                        ),
                    )
                    await page.goto(f"http://127.0.0.1:{port}{prefix}/")
                    await page.get_by_text("Configured", exact=True).wait_for()
                    await page.get_by_role("button", name="Test directory connection").click()
                    await page.get_by_text("Directory bind succeeded.", exact=False).wait_for()
                    await page.locator("#certificate-file").set_input_files(
                        {
                            "name": "ad-ca.pem",
                            "mimeType": "application/x-pem-file",
                            "buffer": test_ca(),
                        }
                    )
                    await page.get_by_role("button", name="Upload certificate", exact=True).click()
                    await page.get_by_text("Certificate saved.", exact=False).wait_for()
                    assert runtime.certificates.uploaded.exists()
                    await page.screenshot(path=str(output / "desktop-light.png"), full_page=True)
                    async with page.expect_download() as download:
                        await page.get_by_role("link", name="Download auth-wrapper.py").click()
                    file = await download.value
                    assert file.suggested_filename == "auth-wrapper.py"
                    await page.get_by_role("button", name="Remove uploaded certificate").click()
                    await page.get_by_role("button", name="Cancel", exact=True).click()
                    assert runtime.certificates.uploaded.exists()
                    await page.get_by_role("button", name="Remove uploaded certificate").click()
                    await page.get_by_role("button", name="Remove certificate", exact=True).click()
                    await page.get_by_text("Uploaded certificate removed.", exact=True).wait_for()
                    assert not runtime.certificates.uploaded.exists()
                    await page.locator("#language").select_option("nb")
                    await page.get_by_role("heading", name="Din katalog. Tilkoblet.").wait_for()
                    await page.get_by_text(
                        "Det opplastede sertifikatet er fjernet.", exact=True
                    ).wait_for()
                    assert "Katalogtilkoblingen" in await page.locator("#check-result").inner_text()
                    await page.emulate_media(color_scheme="dark")
                    await page.screenshot(path=str(output / "desktop-dark-nb.png"), full_page=True)
                    await page.set_viewport_size({"width": 390, "height": 844})
                    await page.screenshot(path=str(output / "mobile-dark-nb.png"), full_page=True)
                    assert await page.evaluate(
                        "document.documentElement.scrollWidth <= window.innerWidth"
                    )
                    assert not errors, errors
                    assert not bad_responses, bad_responses
                    print(
                        "Browser checks passed: Ingress prefix, upload, connection test, download, "
                        "remove/cancel, Norwegian, light/dark and mobile layout."
                    )
                    print(f"Screenshots: {output}")
                finally:
                    await browser.close()
        finally:
            await runner.cleanup()
            runtime.pool.shutdown()
            server.peer_address = original_peer


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--chrome", action="store_true", help="Use a locally installed Chrome")
    asyncio.run(main(parser.parse_args().chrome))
