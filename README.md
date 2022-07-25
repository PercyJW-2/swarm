# swarm

## API Documentation

[On Github Pages](https://jwachsmuth.pages.ub.uni-bielefeld.de/swarm)

## Example Usage

To use the provided example follow these steps:
1. Clone this repository with `git clone https://gitlab.ub.uni-bielefeld.de/jwachsmuth/swarm.git`
2. Change the directory to the example directory with `cd [/path/to/project/root]/example`
3. run `source setup.bash`. This file creates a python virtual environment, installs all dependencies and activates the virtual environment.
4. edit the `ip_list.yaml` file and include all ip addresses of the used devices
5. run `python ExampleUsage.py [index]` where index is the address from `ip_list.yaml` that should be used for this client
6. start more instances of the program to build up the network. (Don't forget to activate the virtual environment if you start the program on the same machine)

## Pip installation

To use this Library in your project you can follow these steps:
1. Download the wheel from the latest build [from here](https://gitlab.ub.uni-bielefeld.de/jwachsmuth/swarm/-/jobs/artifacts/main/download?job=run)
2. unzip the downloaded file
3. run `pip install /path/to/downloaded/whl/file`

You can also just clone this repository and install it with `pip install /path/to/library/root`
