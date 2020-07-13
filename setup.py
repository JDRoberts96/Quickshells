from setuptools import setup, find_packages

setup(
    name='QuickShells',
    version='0.1',
    author='https://github.com/JDRoberts96',
    description='A simple Python3 program to automate generating reverse shell code, copying it to the clipboard and '
                'opening up a netcat listener on the specified port.',
    packages=find_packages(),
    scripts=["QuickShells.py"]

)