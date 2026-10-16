import time
from pathlib import Path
from playwright.sync_api import sync_playwright

CHROME_PATH = r"C:\Users\user\AppData\Local\ms-playwright\chromium-1234\chrome-win64\chrome.exe"
PROXY = "socks5://31.77.19.92:443"
TARGET_URL = "https://wgm.wien.at/usage/index.html"

NAV_TIMEOUT_MS = 600_000
HOLD_OPEN_MS  = 3_600_000


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def main() -> int:
    if not Path(CHROME_PATH).is_file():
        log(f"ERROR: Chromium not found at {CHROME_PATH}")
        return 2

    with sync_playwright() as p:
        log("Launching Chromium...")
        browser = p.chromium.launch(
            headless=False,
            executable_path=CHROME_PATH,
            args=[
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--proxy-bypass-list=<-loopback>",
                "--ignore-certificate-errors",
                "--disable-blink-features=AutomationControlled",
            ],
        )

        log(f"Creating context with proxy {PROXY}")
        context = browser.new_context(
            proxy={"server": PROXY},
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1280, "height": 800},
            locale="en-US",
        )

        # THIS is what makes the challenge pass — patch webdriver before page JS runs
        context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            window.chrome = { runtime: {} };
        """)

        page = context.new_page()
        page.set_default_navigation_timeout(NAV_TIMEOUT_MS)
        page.set_default_timeout(NAV_TIMEOUT_MS)

        log(f"Navigating to {TARGET_URL}")
        try:
            page.goto(TARGET_URL, wait_until="domcontentloaded")
            log("Navigation returned.")
        except Exception as e:
            log(f"Navigation error: {e}")

        log(f"Holding browser open for {HOLD_OPEN_MS/1000:.0f}s.")
        try:
            page.wait_for_timeout(HOLD_OPEN_MS)
        except Exception:
            pass

        context.close()
        browser.close()

    return 0


if __name__ == "__main__":
    main()
