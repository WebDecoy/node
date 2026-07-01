"""
Live botasaurus test against the WebDecoy stealth harness.

Prereqs:
    pip install botasaurus
    npx tsx harness/server.ts        # in another terminal (serves :8787)

Then:
    python3 harness/botasaurus_test.py

It drives botasaurus in BOTH modes against the harness and prints the real
DetectionEngine verdict the server returns:
  - browser mode  -> loads the page, the page collects real signals & scores
  - request mode  -> GET /probe (no JS; scored on UA + headers only)

API note: botasaurus's surface shifts across versions; if `driver.select`/`.get`
differ in your version, adjust the two marked lines. The verdict also prints on
the SERVER stdout regardless, so you can read results there too.
"""

HARNESS = "http://localhost:8787"


def run_browser_mode() -> None:
    try:
        from botasaurus.browser import browser, Driver
    except Exception as e:  # noqa: BLE001
        print(f"[browser] botasaurus import failed: {e}")
        return

    @browser(headless=True, block_images=True)
    def scrape(driver: "Driver", data):  # noqa: ANN001
        driver.get(f"{HARNESS}/")             # <- adjust if your botasaurus differs
        driver.sleep(3)                        # let the page collect + POST /score
        try:
            text = driver.select("#result").text   # <- adjust selector API if needed
        except Exception:                      # noqa: BLE001
            text = driver.run_js("return document.getElementById('result').textContent")
        print("\n===== BOTASAURUS BROWSER MODE — server verdict =====")
        print(text)
        return text

    scrape()


def run_request_mode() -> None:
    try:
        from botasaurus.request import request, Request
    except Exception as e:  # noqa: BLE001
        print(f"[request] botasaurus import failed: {e}")
        return

    @request
    def fetch(req: "Request", data):  # noqa: ANN001
        r = req.get(f"{HARNESS}/probe")
        print("\n===== BOTASAURUS REQUEST MODE (@request) — server verdict =====")
        print(r.text)
        return r.text

    fetch()


if __name__ == "__main__":
    run_browser_mode()
    run_request_mode()
