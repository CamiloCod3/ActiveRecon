from setuptools import find_packages, setup


setup(
    name="activerecon",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "dnspython",
        "pyyaml",
    ],
    entry_points={
        "console_scripts": [
            "activerecon=activerecon.main:main",
        ],
    },
    include_package_data=True,
    description="Active Recon: An automated reconnaissance tool",
    author="CamiloCod3",
    url="https://github.com/CamiloCod3/ActiveRecon",
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
