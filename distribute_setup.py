from setuptools import setup

setup(
    name='pebel',
    version='0.2.0',
    author='Jan de Muijnck-Hughes',
    author_email='jfdm@st-andrews.ac.uk',
    packages=['pebel'],
    scripts=['scripts/pyCPABE-decrypt.py',
             'scripts/pyCPABE-encrypt.py',
             'scripts/pyCPABE-keygen.py',
             'scripts/pyCPABE-setup.py',
             'scripts/pyKPABE-decrypt.py',
             'scripts/pyKPABE-encrypt.py',
             'scripts/pyKPABE-keygen.py',
             'scripts/pyKPABE-setup.py'],
    url='https://github.com/jfdm/pyPEBEL',
    license='BSD-new',
    description='A python 3.x module to support the use of the IBE, ABE, and PBE family of asymmetric encryption schemes within python scripts and modules.',
    long_description=open('README.markdown').read(),
    install_requires=[
        "setuptools",
        "pyparsing >= 1.5.5",
        "pycrypto >= 2.6",
        "Charm-Crypto >= 0.42",
    ],
    classifiers = [
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Development Status :: 4 - Beta",
        "Environment :: COnsole",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Scientific/Engineering",
        "Topic :: Security :: Cryptography",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research"
        ]
)
