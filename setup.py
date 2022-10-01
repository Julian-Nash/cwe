import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="cwe2",
    version="2.0.0",
    packages=setuptools.find_packages(),
    author="Julian Nash",
    include_package_data=True,
    install_requires=[""],
    author_email="julianjamesnash@gmail.com",
    description="Common weakness enumeration wrapper for Python, fork from https://github.com/Julian-Nash/cwe",
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords="cwe2",
    url="https://github.com/nexB/cwe2",
    project_urls={
        "Bug Tracker": "https://github.com/nexB/cwe2/issues",
        "Documentation": "https://github.com/nexB/cwe2",
        "Source Code": "https://github.com/nexB/cwe2",
    },
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
)
