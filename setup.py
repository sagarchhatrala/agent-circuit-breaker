from pathlib import Path

from setuptools import find_packages, setup


ROOT = Path(__file__).parent
README = (ROOT / "README.md").read_text(encoding="utf-8")

setup(
    name="agent-circuit-breaker",
    version="1.5.1",
    description="Deterministic safety gate for AI coding agents",
    long_description=README,
    long_description_content_type="text/markdown",
    author="Sagar Chhatrala",
    author_email="sagarchhatrala2234@gmail.com",
    url="https://github.com/sagarchhatrala/agent-circuit-breaker",
    project_urls={
        "Homepage": "https://github.com/sagarchhatrala/agent-circuit-breaker",
        "Documentation": "https://github.com/sagarchhatrala/agent-circuit-breaker/tree/main/docs",
        "Source": "https://github.com/sagarchhatrala/agent-circuit-breaker",
        "Issues": "https://github.com/sagarchhatrala/agent-circuit-breaker/issues",
        "Releases": "https://github.com/sagarchhatrala/agent-circuit-breaker/releases",
    },
    license="MIT",
    license_files=["LICENSE"],
    packages=find_packages(exclude=("tests", "tests.*")),
    python_requires=">=3.11",
    install_requires=[],
    extras_require={
        "redis": ["redis>=5"],
        "otel": ["opentelemetry-api>=1.25"],
        "prometheus": ["prometheus-client>=0.20"],
        "enterprise": ["redis>=5", "opentelemetry-api>=1.25", "prometheus-client>=0.20"],
    },
    entry_points={
        "console_scripts": [
            "circuit-breaker=agent_circuit_breaker.cli:main",
            "circuit-breaker-mcp-proxy=agent_circuit_breaker_mcp.proxy:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: System :: Systems Administration",
    ],
    keywords="security safety ai-agents mcp circuit-breaker deterministic",
)
