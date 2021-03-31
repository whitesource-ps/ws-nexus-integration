import setuptools

setuptools.setup(
    name="ws-nexus",
    version="0.1.0",
    author="WhiteSource Professional Services",
    author_email="ps@whitesourcesoftware.com",
    description="WS Nexus Integration",
    url='https://github.com/whitesource-ps/ws-nexus',
    license='LICENSE',
    packages=setuptools.find_packages(),
    python_requires='>=3.6',
    install_requires=open('requirements.txt').read().splitlines(),
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
