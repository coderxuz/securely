from setuptools import setup, find_packages

setup(
    name="securely",
    version="0.1.7",  # Make sure to update with every release
    author="Xursand",
    author_email="coderxuz2009@gmail.com",
    description="This package will help you while authorization and authentication in fastapi",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/coderxuz/securely",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        'passlib',
        'authlib'# Add any required dependencies
    ],
)
