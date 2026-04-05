import copy
from typing import Optional, Any
from core.config import ScanContext, xsschecker
from core.checker import XSSChecker
from core.generator import PayloadGenerator
from core.htmlParser import HTMLParser
from core.requester import requester
from core.log import setup_logger

logger = setup_logger()

class Scanner:
    def __init__(self, context: ScanContext):
        self.context = context
        self.checker = XSSChecker(context)
        self.generator = PayloadGenerator(context)
        self.parser = HTMLParser(context)

    def scan(self, skip_dom: bool = False, skip_confirm: bool = False):
        """
        Performs the main scan on the target.
        """
        logger.run(f"Scanning {self.context.target}...")
        
        # 1. Initial Request to check for reflections
        # We replace the placeholder in params with our checker string
        # If no placeholder, we might need a different approach (Arjun)
        
        try:
            response = requester(
                self.context.target, 
                self.context.paramData, 
                self.context.headers, 
                True, # GET
                self.context.config.delay, 
                self.context.config.timeout
            )
            response_text = response.text
        except Exception as e:
            logger.error(f"Request failed: {e}")
            return

        # 2. Parse HTML to find reflections
        occurences = self.parser.parse(response_text)
        
        if not occurences:
            logger.info("No reflections found.")
            return

        logger.good(f"Found {len(occurences)} reflections.")

        # 3. Analyze filter efficiency (Simplified for now)
        # In a real scenario, we'd send probes like < > " ' and call parser.calculate_scores
        for pos in occurences:
            occurences[pos]['score'] = {'<': 100, '>': 100, '\"': 100, '\'': 100}

        # 4. Generate Payloads
        vectors = self.generator.generate(occurences, response_text)
        
        # 5. Check Payloads
        total_found = 0
        for level in sorted(vectors.keys(), reverse=True):
            for payload in vectors[level]:
                efficiencies = self.checker.check(payload, list(occurences.keys()))
                if efficiencies:
                    logger.vuln(f"Vulnerability found! Payload: {payload} (Level {level})")
                    total_found += 1
                    if total_found >= 5 and not skip_confirm:
                        # User interaction here...
                        break
            if total_found >= 5 and not skip_confirm:
                break

        if total_found == 0:
            logger.info("Scan completed. No vulnerabilities found.")
        else:
            logger.good(f"Scan completed. Total vulnerabilities found: {total_found}")
