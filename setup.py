import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as fh:
    dependencies = fh.read()

setuptools.setup(
    name="cwe",
    version="0.1",
    packages=setuptools.find_packages(),
    install_requires=dependencies,
    author="Julian Nash",
    author_email="julianjamesnash@gmail.com",
    description="Common weakness enumeration wrapper for Python",
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords="python example",
    url="https://github.com/Julian-Nash/cwe",
    project_urls={
        "Bug Tracker": "https://github.com/Julian-Nash/cwe",
        "Documentation": "https://github.com/Julian-Nash/cwe",
        "Source Code": "https://github.com/Julian-Nash/cwe",
    },
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
)