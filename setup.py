from setuptools import setup

with open('README.md', 'r') as fh:
    long_description = fh.read()

setup(
    name='coinigy',
    version='0.1a.dev',
    author='Hunter M. Allen',
    author_email='allenhm@gmail.com',
    license='MIT',
    packages=['coinigy'],
    install_requires=['numpy>=1.14.3',
                      'pandas>=0.23.0',
                      'peakutils>=1.1.1',
                      'plotly>=2.6.0'],
    description=('Python bindings for Coinigy API functions. \
                  Not much more than the original examples with \
                  a cleaned-up working directory and packaged \
                  as installer with setuptools.'),
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/hmallen/coinigy',
    keywords=['coinigy'],
    classifiers=(
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ),
)