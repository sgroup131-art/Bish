from setuptools import setup, find_packages

setup(
    name="Bish",
    version="1.0.0",
    author="Muhammad Baloch",
    author_email="sgroup131@gmail.com",  # optional
    description="Bish - Phishing & Vulnerability Scanner",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/Bish",  # replace with your repo link
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "python-whois>=0.8.0",
        "colorama>=0.4.6",
        "pyOpenSSL>=24.0.0",
        "dnspython>=2.6.1",
        "validators>=0.22.0",
    ],
    entry_points={
        "console_scripts": [
            "bish=bish.bish:main",  # lets you run `bish` directly in terminal
        ],
    },
)

