"""Playwright attached-mode capture (P1, optional).

Connects to an existing browser via CDP and extracts a region-annotated
accessibility snapshot plus a screenshot. Requires:

    pip install playwright && playwright install chromium
"""
import io
from typing import List, Tuple

# Only interactive roles matter for action authorization; text/layout nodes
# (StaticText / InlineTextBox / generic ...) are noise.
INTERACTIVE_ROLES = {
    "button", "link", "textbox", "checkbox", "radio", "menuitem", "tab",
    "combobox", "listbox", "option", "switch", "slider", "searchbox",
    "spinbutton", "menuitemcheckbox", "menuitemradio", "gridcell", "cell",
}


def _keep(role: str) -> bool:
    return role.lower() in INTERACTIVE_ROLES


def _flatten_with_regions(page) -> List[dict]:
    """Interactive a11y nodes with regions via CDP AXTree + Playwright locator."""
    cdp = page.context.new_cdp_session(page)
    nodes: List[dict] = []
    try:
        cdp.send("Accessibility.enable")
        try:
            ax = cdp.send("Accessibility.getFullAXTree")
        except Exception:
            return _flatten_no_region(page)

        for n in ax.get("nodes", []):
            role = (n.get("role") or {}).get("value", "")
            name = (n.get("name") or {}).get("value", "")
            if not _keep(role) or not name:
                continue
            region = None
            try:
                box = page.get_by_role(role, name=name, exact=True).first.bounding_box()
                if box:
                    region = [
                        int(box["x"]), int(box["y"]),
                        int(box["x"] + box["width"]), int(box["y"] + box["height"]),
                    ]
            except Exception:
                pass
            nodes.append({"role": role, "name": name, "region": region, "confidence": 0.99})
        return nodes
    finally:
        cdp.detach()


def _flatten_no_region(page) -> List[dict]:
    """Fallback: Playwright a11y snapshot without bounding boxes."""
    try:
        tree = page.accessibility.snapshot()
    except Exception:
        return []
    nodes: List[dict] = []

    def walk(node):
        role = node.get("role", "")
        name = node.get("name", "")
        if _keep(role) and name:
            nodes.append({"role": role, "name": name, "region": None, "confidence": 0.99})
        for child in node.get("children", []) or []:
            walk(child)

    if tree:
        walk(tree)
    return nodes


def capture_attached(cdp_endpoint: str) -> Tuple[object, List[dict]]:
    """Return ``(PIL Image, a11y snapshot)``. Raises if playwright is missing."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        raise RuntimeError(
            "attached mode requires playwright: "
            "pip install playwright && playwright install chromium"
        ) from exc

    from PIL import Image

    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(cdp_endpoint)
        try:
            contexts = browser.contexts
            if not contexts:
                raise RuntimeError("no browser context at CDP endpoint")
            pages = contexts[0].pages
            if not pages:
                raise RuntimeError("no page available")
            page = pages[0]
            # a11y box model is in CSS px; screenshot is in device px. Scale.
            try:
                dpr = float(page.evaluate("window.devicePixelRatio"))
            except Exception:
                dpr = 1.0
            image = Image.open(io.BytesIO(page.screenshot())).convert("RGB")
            snapshot = _flatten_with_regions(page)
            if dpr != 1.0:
                for node in snapshot:
                    if node.get("region"):
                        node["region"] = [int(v * dpr) for v in node["region"]]
        finally:
            browser.close()
    return image, snapshot


def capture_a11y(cdp_endpoint: str) -> dict:
    """Extract only the page title + interactive a11y elements (no screenshot).

    Used by the /browser_state endpoint so the agent can "read" the page
    without the (slow / timeout-prone) screenshot step.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        raise RuntimeError("playwright required for CDP access") from exc

    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(cdp_endpoint)
        try:
            pages = browser.contexts[0].pages if browser.contexts else []
            if not pages:
                return {"title": "", "elements": []}
            page = pages[0]
            title = page.title()
            elements = _flatten_with_regions(page)
            return {"title": title, "elements": elements}
        finally:
            browser.close()
