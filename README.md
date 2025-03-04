# HolBA BIR support in Angr
Python package for HolBA BIR support for Angr framework.

## Add frozen dependencies
Take the list of dependencies of the desired package with `python3 -m pip show PACKAGENAME` (e.g., for `angr`).
Read the version numbers of all installed packages with `python3 -m pip freeze`.
Only take the rows with the dependencies of the desired package and write them in `requirements.txt`.

## Run without package install
`python3 symbolic_execution_wrapper.py magicinput.bir`

## Install package
`python3 -m pip install git+https://github.com/Tiziano-M/fence_insertion.git@main`

## Uninstall package
`python3 -m pip uninstall bir_angr`

## Show package metadata
`python3 -m pip show bir_angr`

## Upgrade package
`python3 -m pip install --upgrade git+https://github.com/Tiziano-M/fence_insertion.git@main`

## Run symbolic execution after package installation
`python3 -m bir_angr.symbolic_execution magicinput.bir`

