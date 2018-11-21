"""

(c) 2018 Adobe. All rights reserved.
This file is licensed to you under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License. You may obtain a copy
of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
OF ANY KIND, either express or implied. See the License for the specific language
governing permissions and limitations under the License.

"""


from setuptools import setup
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

APP_VERSION = "2.0.13"
APP_AUTHOR = "Jed Glazner, Sandeep Srivastav Vaddiparthy, Florian Noeding, Heiko Hahn"
APP_NAME = "messer"

# this is a bit of a hack to print out a properties file for jenkins to pickup which,
# will allow us to know the name of the artifact that we need to upload to S3.
if __name__ == "__main__":
    f = open('jenkins.properties', 'w')
    f.write("ARTIFACT_FILE={0}-{1}.tar.gz\n".format(APP_NAME, APP_VERSION))
    f.write("ARTIFACT_VERSION={0}\n".format(APP_VERSION))
    f.write("ARTIFACT_NAME={0}\n".format(APP_NAME))
    f.close()

setup(
    name=APP_NAME,
    version=APP_VERSION,
    description="An Amazon/Azure databag replacment for knife.",
    long_description="",
    url="https://github.com/adobe/messer/",
    author=APP_AUTHOR,
    license="Apache 2.0",
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',

        # Pick your license as you wish (should match "license" above)
        'License :: "Apache 2.0',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 2.7',
    ],

    keywords='aws azure secrets credentials knife',

    packages=['messer'],

    package_data={'messer': ['*']},

    install_requires=["cryptography==2.1.4",
                      "boto==2.48.0",
                      "argparse==1.4.0",
                      "appdirs==1.4.0",
                      "azure==2.0.0",
                      "adal==0.5.1"],

    entry_points={
        'console_scripts': [
            'messer=messer:main',
        ],
    },
)
