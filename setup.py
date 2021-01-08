from setuptools import setup, find_packages

setup(name='kfinny.avclass',
      version='3.0',
      description="A package for malicialab's avclass",
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
