"""HTTP-Smuggler setup file."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

setup(
    name="http-smuggler",
    version="1.1.0",
    author="HTTP-Smuggler Contributors",
    author_email="security@example.com",
    description="Comprehensive HTTP Request Smuggling Detection & Exploitation Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/http-smuggler",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/http-smuggler/issues",
        "Source": "https://github.com/yourusername/http-smuggler",
        "Documentation": "https://github.com/yourusername/http-smuggler#readme",
    },
    packages=find_packages(exclude=["tests", "tests.*", "docs"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords=[
        "security",
        "http",
        "smuggling",
        "request-smuggling",
        "penetration-testing",
        "vulnerability-scanner",
        "http2",
        "websocket",
    ],
    python_requires=">=3.9",
    install_requires=[
        "aiohttp>=3.9.0",
        "aiofiles>=23.0.0",
        "h2>=4.1.0",
        "hyperframe>=6.0.1",
        "hpack>=4.0.0",
        "httpx[http2]>=0.25.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
        "click>=8.1.0",
        "rich>=13.0.0",
        "pydantic>=2.5.0",
        "pyyaml>=6.0.1",
        "structlog>=23.2.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "mypy>=1.5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "http-smuggler=http_smuggler.main:cli",
        ],
    },
)
