from setuptools import setup, find_packages

setup(
    name="agent-circuit-breaker",
    version="0.7.0a1",
    description="Deterministic safety layer for AI coding agents",
    author="Sagar Chhatrala",
    author_email="sagarchhatrala2234@gmail.com",
    url="https://github.com/sagarchhatrala/agent-circuit-breaker",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[],
    entry_points={
        "console_scripts": [
            "circuit-breaker=agent_circuit_breaker.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    keywords="security safety ai-agents circuit-breaker deterministic",
)
