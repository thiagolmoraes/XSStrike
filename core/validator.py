import asyncio
from playwright.async_api import async_playwright
from typing import Optional, Dict, Any
from core.config import ScanContext

class DynamicValidator:
    def __init__(self, context: ScanContext):
        self.context = context

    async def validate(self, url: str, params: Dict[str, Any]) -> bool:
        """
        Validates a potential XSS vulnerability using a headless browser.
        It checks if an alert/confirm/prompt is triggered.
        """
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            
            # Setup alert listener
            triggered = asyncio.Event()
            page.on("dialog", lambda dialog: triggered.set())
            
            try:
                # Basic URL construction (this needs refinement based on GET/POST)
                # For now, let's assume simple GET for the prototype
                query = "&".join([f"{k}={v}" for k, v in params.items()])
                full_url = f"{url}?{query}" if "?" not in url else f"{url}&{query}"
                
                await page.goto(full_url, timeout=self.context.config.timeout * 1000)
                
                # Wait a bit for execution
                try:
                    await asyncio.wait_for(triggered.wait(), timeout=2.0)
                    return True
                except asyncio.TimeoutError:
                    return False
            except Exception as e:
                # Logger should be injected here
                print(f"Validation error: {e}")
                return False
            finally:
                await browser.close()

def run_validation(url: str, params: Dict[str, Any], context: ScanContext) -> bool:
    """Synchronous wrapper for the async validator."""
    validator = DynamicValidator(context)
    return asyncio.run(validator.validate(url, params))
