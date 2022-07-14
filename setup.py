from setuptools import setup, find_packages

setup(
    name='swarm',
    version='0.0.1',
    description='',
    url='https://gitlab.ub.uni-bielefeld.de/jwachsmuth/swarm',
    author='Joris Wachsmuth',
    author_email='jwachsmuth@techfak.de',
    license='GNU LGPLv3',
    packages=find_packages(
        where='.',
        include=['swarm*'],
        exclude=['swarm.tests']
    ),
    install_requires=[],
    classifiers=[
        'Development Status :: 1 - Planning',
        'Operating System :: POSIX :: Linux',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python :: 3.10'
    ],
)
