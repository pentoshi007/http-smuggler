"""Async domain crawler for HTTP Smuggler.

Crawls target domain to discover endpoints for testing:
- Follows links within same origin
- Parses forms to find POST endpoints
- Respects robots.txt
- Rate limiting and depth control
"""

import asyncio
import re
from typing import Optional, List, Set, Dict, Any
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlunparse
from html.parser import HTMLParser

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector

from http_smuggler.core.config import CrawlConfig
from http_smuggler.core.models import Endpoint
from http_smuggler.core.exceptions import CrawlError, CrawlDepthExceededError
from http_smuggler.utils.helpers import (
    parse_url,
    normalize_url,
    is_same_origin,
    RateLimiter,
)


@dataclass
class CrawlResult:
    """Results from domain crawling."""
    endpoints: List[Endpoint]
    pages_visited: int
    errors: List[str] = field(default_factory=list)
    robots_parsed: bool = False
    sitemap_parsed: bool = False


class LinkExtractor(HTMLParser):
    """HTML parser to extract links and forms."""
    
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self._current_form: Optional[Dict[str, Any]] = None
    
    def handle_starttag(self, tag: str, attrs: List[tuple]):
        attrs_dict = dict(attrs)
        
        # Extract links from <a> tags
        if tag == "a" and "href" in attrs_dict:
            href = attrs_dict["href"]
            url = self._resolve_url(href)
            if url:
                self.links.add(url)
        
        # Extract links from <link> tags (stylesheets, etc.)
        if tag == "link" and "href" in attrs_dict:
            href = attrs_dict["href"]
            url = self._resolve_url(href)
            if url:
                self.links.add(url)
        
        # Extract forms
        if tag == "form":
            action = attrs_dict.get("action", "")
            method = attrs_dict.get("method", "GET").upper()
            url = self._resolve_url(action) or self.base_url
            
            self._current_form = {
                "action": url,
                "method": method,
                "inputs": [],
            }
        
        # Extract form inputs
        if tag == "input" and self._current_form:
            input_name = attrs_dict.get("name")
            input_type = attrs_dict.get("type", "text")
            if input_name:
                self._current_form["inputs"].append({
                    "name": input_name,
                    "type": input_type,
                })
    
    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form:
            self.forms.append(self._current_form)
            self._current_form = None
    
    def _resolve_url(self, href: str) -> Optional[str]:
        """Resolve relative URL to absolute."""
        if not href:
            return None
        
        # Skip javascript:, mailto:, etc.
        if any(href.startswith(p) for p in ["javascript:", "mailto:", "tel:", "#", "data:"]):
            return None
        
        # Resolve relative URLs
        url = urljoin(self.base_url, href)
        
        # Normalize and return
        return normalize_url(url)


class RobotsParser:
    """Simple robots.txt parser."""
    
    def __init__(self):
        self.disallowed: Set[str] = set()
        self.allowed: Set[str] = set()
        self.sitemaps: List[str] = []
    
    def parse(self, content: str) -> None:
        """Parse robots.txt content."""
        current_applies = False
        
        for line in content.split("\n"):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue
            
            # Check user-agent
            if line.lower().startswith("user-agent:"):
                agent = line.split(":", 1)[1].strip().lower()
                current_applies = agent in ["*", "httpsmuggler"]
            
            # Disallow rules
            elif line.lower().startswith("disallow:") and current_applies:
                path = line.split(":", 1)[1].strip()
                if path:
                    self.disallowed.add(path)
            
            # Allow rules
            elif line.lower().startswith("allow:") and current_applies:
                path = line.split(":", 1)[1].strip()
                if path:
                    self.allowed.add(path)
            
            # Sitemap
            elif line.lower().startswith("sitemap:"):
                sitemap = line.split(":", 1)[1].strip()
                self.sitemaps.append(sitemap)
    
    def is_allowed(self, path: str) -> bool:
        """Check if a path is allowed by robots.txt."""
        # Check allow rules first (more specific)
        for allowed in self.allowed:
            if path.startswith(allowed):
                return True
        
        # Check disallow rules
        for disallowed in self.disallowed:
            if path.startswith(disallowed):
                return False
        
        return True


class DomainCrawler:
    """Async domain crawler for endpoint discovery."""
    
    def __init__(self, config: Optional[CrawlConfig] = None):
        self.config = config or CrawlConfig()
        self.rate_limiter = RateLimiter(
            requests_per_second=self.config.requests_per_second
        )
        
        # Crawl state
        self._visited: Set[str] = set()
        self._endpoints: List[Endpoint] = []
        self._errors: List[str] = []
        self._robots: Optional[RobotsParser] = None
        
        # Regex for excluding patterns
        self._exclude_patterns = [
            re.compile(p) for p in self.config.exclude_patterns
        ]
    
    async def crawl(self, start_url: str) -> CrawlResult:
        """Crawl domain starting from URL.
        
        Args:
            start_url: Starting URL for crawl
        
        Returns:
            CrawlResult with discovered endpoints
        """
        # Reset state
        self._visited.clear()
        self._endpoints.clear()
        self._errors.clear()
        self._robots = None
        
        parsed = parse_url(start_url)
        origin = parsed.origin
        
        # Create aiohttp session
        timeout = ClientTimeout(
            total=30,
            connect=10,
        )
        connector = TCPConnector(
            limit=self.config.concurrent_requests,
            ssl=False,  # Don't verify SSL for crawling
        )
        
        async with ClientSession(
            timeout=timeout,
            connector=connector,
            headers={"User-Agent": self.config.user_agent},
            cookies=self.config.cookies,
        ) as session:
            # Fetch and parse robots.txt
            if self.config.respect_robots_txt:
                await self._fetch_robots(session, origin)
            
            # Parse sitemap if available
            if self.config.parse_sitemap and self._robots and self._robots.sitemaps:
                for sitemap_url in self._robots.sitemaps[:3]:  # Limit sitemaps
                    await self._parse_sitemap(session, sitemap_url, origin)
            
            # Start crawling
            queue = asyncio.Queue()
            await queue.put((start_url, 0))
            
            workers = [
                asyncio.create_task(self._worker(session, queue, origin))
                for _ in range(self.config.concurrent_requests)
            ]
            
            # Wait for queue to be processed
            await queue.join()
            
            # Cancel workers
            for worker in workers:
                worker.cancel()
            
            await asyncio.gather(*workers, return_exceptions=True)
        
        return CrawlResult(
            endpoints=self._endpoints[:self.config.max_endpoints],
            pages_visited=len(self._visited),
            errors=self._errors,
            robots_parsed=self._robots is not None,
            sitemap_parsed=bool(self._robots and self._robots.sitemaps),
        )
    
    async def _worker(
        self,
        session: ClientSession,
        queue: asyncio.Queue,
        origin: str,
    ) -> None:
        """Worker coroutine for crawling."""
        while True:
            try:
                url, depth = await queue.get()
                
                try:
                    # Check limits
                    if len(self._visited) >= self.config.max_pages:
                        queue.task_done()
                        continue
                    
                    if len(self._endpoints) >= self.config.max_endpoints:
                        queue.task_done()
                        continue
                    
                    if depth > self.config.max_depth:
                        queue.task_done()
                        continue
                    
                    # Skip already visited
                    if url in self._visited:
                        queue.task_done()
                        continue
                    
                    # Skip excluded patterns
                    if self._should_exclude(url):
                        queue.task_done()
                        continue
                    
                    # Check robots.txt
                    parsed = urlparse(url)
                    if self._robots and not self._robots.is_allowed(parsed.path):
                        queue.task_done()
                        continue
                    
                    # Rate limiting
                    await self.rate_limiter.acquire()
                    
                    # Mark as visited
                    self._visited.add(url)
                    
                    # Fetch page
                    links, forms = await self._fetch_and_parse(session, url)
                    
                    # Add endpoint for this URL
                    self._endpoints.append(Endpoint(
                        url=url,
                        method="GET",
                        discovered_from=None if depth == 0 else "crawl",
                    ))
                    
                    # Add form endpoints
                    for form in forms:
                        if form["method"] == "POST":
                            self._endpoints.append(Endpoint(
                                url=form["action"],
                                method="POST",
                                accepts_body=True,
                                content_type="application/x-www-form-urlencoded",
                                discovered_from=url,
                            ))
                    
                    # Queue new links
                    for link in links:
                        if is_same_origin(link, origin):
                            if link not in self._visited:
                                await queue.put((link, depth + 1))
                
                except Exception as e:
                    self._errors.append(f"Error crawling {url}: {str(e)}")
                
                finally:
                    queue.task_done()
                    
            except asyncio.CancelledError:
                break
    
    async def _fetch_and_parse(
        self,
        session: ClientSession,
        url: str,
    ) -> tuple:
        """Fetch URL and extract links/forms.
        
        Returns:
            Tuple of (links, forms)
        """
        try:
            async with session.get(
                url,
                allow_redirects=self.config.follow_redirects,
                max_redirects=self.config.max_redirects,
            ) as response:
                # Only parse HTML
                content_type = response.headers.get("Content-Type", "")
                if "text/html" not in content_type:
                    return set(), []
                
                html = await response.text()
                
                # Parse HTML
                extractor = LinkExtractor(url)
                try:
                    extractor.feed(html)
                except Exception:
                    pass
                
                return extractor.links, extractor.forms
                
        except Exception:
            return set(), []
    
    async def _fetch_robots(
        self,
        session: ClientSession,
        origin: str,
    ) -> None:
        """Fetch and parse robots.txt."""
        robots_url = f"{origin}/robots.txt"
        
        try:
            async with session.get(robots_url) as response:
                if response.status == 200:
                    content = await response.text()
                    self._robots = RobotsParser()
                    self._robots.parse(content)
        except Exception:
            pass
    
    async def _parse_sitemap(
        self,
        session: ClientSession,
        sitemap_url: str,
        origin: str,
    ) -> None:
        """Parse sitemap.xml for URLs."""
        try:
            async with session.get(sitemap_url) as response:
                if response.status != 200:
                    return
                
                content = await response.text()
                
                # Simple regex extraction of URLs from sitemap
                url_pattern = re.compile(r"<loc>([^<]+)</loc>")
                
                for match in url_pattern.finditer(content):
                    url = match.group(1)
                    if is_same_origin(url, origin):
                        self._endpoints.append(Endpoint(
                            url=url,
                            method="GET",
                            discovered_from="sitemap",
                        ))
                        
                        if len(self._endpoints) >= self.config.max_endpoints:
                            break
                            
        except Exception:
            pass
    
    def _should_exclude(self, url: str) -> bool:
        """Check if URL should be excluded based on patterns."""
        for pattern in self._exclude_patterns:
            if pattern.search(url):
                return True
        return False


async def crawl_domain(
    url: str,
    config: Optional[CrawlConfig] = None,
) -> CrawlResult:
    """Convenience function to crawl a domain.
    
    Args:
        url: Starting URL
        config: Optional crawl configuration
    
    Returns:
        CrawlResult with discovered endpoints
    """
    crawler = DomainCrawler(config)
    return await crawler.crawl(url)

