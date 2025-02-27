from setuptools import setup, find_packages

setup(
    name='rule-engine',
    version='0.1.0',
    description='A rule engine for parsing, executing, converting, and integrating rules with SIEM systems.',
    author='Your Name',
    author_email='your.email@example.com',
    url='https://github.com/khulnasoft/rule-engine',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Flask',
        'Click',
        # Add other dependencies here
    ],
    entry_points={
        'console_scripts': [
            'rule-engine=cli.main:cli',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)