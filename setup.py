from setuptools import setup, find_packages

setup(
    name="fatah2",
    version="2.0.0",
    description="Fatah2 — Advanced Recon Suite by Pr0fessor SnApe",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Pr0fessor SnApe",
    license="MIT",
    python_requires=">=3.11",
    packages=find_packages(include=["src", "src.*"]),
    install_requires=[
        "click>=8.1.7",
        "httpx>=0.27.0",
        "aiohttp>=3.9.5",
        "fastapi>=0.111.0",
        "uvicorn[standard]>=0.29.0",
        "pydantic>=2.7.0",
        "dnspython>=2.6.1",
        "python-whois>=0.9.4",
        "pyyaml>=6.0.1",
    ],
    entry_points={
        "console_scripts": [
            "fatah2=fatah2:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
