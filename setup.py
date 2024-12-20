from setuptools import setup, find_packages

setup(
    name="securely",  # Replace with your package's name
    version="0.1.0",  # Initial version
    author="Xursand",
    author_email="coderxuz2009@gmail.com",
    description="This package will help you while authorization and authentication in fastapi",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/my_package",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
