from setuptools import setup, find_packages

with open('README.md', 'r') as fd:
      long_description = fd.read()

setup(name='kfinny.avclass',
      version='3.0.1',
      description="A package for malicialab's avclass",
      long_description=long_description,
      long_description_content_type="text/markdown",
      url='https://github.com/kfinny/avclass-lib',
      author='Kevin Finnigin',
      author_email='kevin@finnigin.net',
      license='MIT',
      packages=find_packages(),
      install_requires=[
            'vt-py'
      ],
      zip_safe=False,
      include_package_data=True)
