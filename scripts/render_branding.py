import argparse
import asyncio
from pathlib import Path

from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parents[1]


async def main(chrome: bool):
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True, **({"channel": "chrome"} if chrome else {})
        )
        try:
            page = await browser.new_page()
            for name in ("icon", "logo"):
                source = (ROOT / "branding" / f"{name}.svg").read_text(encoding="utf-8")
                await page.set_content(f"<style>body {{ margin: 0 }}</style>{source}")
                await page.locator("svg").screenshot(
                    path=str(ROOT / "ldapauth" / f"{name}.png"), omit_background=True
                )
        finally:
            await browser.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--chrome", action="store_true")
    asyncio.run(main(parser.parse_args().chrome))
