#!/bin/bash

function usage {
  echo "Usage: $0 [OPTION]..."
  echo "Run Quantum's test suite(s)"
  echo ""
  echo "  -V, --virtual-env        Always use virtualenv.  Install automatically if not present"
  echo "  -N, --no-virtual-env     Don't use virtualenv.  Run tests in local environment"
  echo "  -c, --coverage           Generate coverage report"
  echo "  -f, --force              Force a clean re-build of the virtual environment. Useful when dependencies have been added."
  echo "  -p, --pep8               Just run pep8"
  echo "  -P, --no-pep8            Don't run pep8"
  echo "  -l, --pylint             Just run pylint"
  echo "  -v, --verbose            Run verbose pylint analysis"
  echo "  -h, --help               Print this usage message"
  echo ""
  echo "Note: with no options specified, the script will try to run the tests in a virtual environment,"
  echo "      If no virtualenv is found, the script will ask if you would like to create one.  If you "
  echo "      prefer to run tests NOT in a virtual environment, simply pass the -N option."
  exit
}

function process_option {
  case "$1" in
    -h|--help) usage;;
    -V|--virtual-env) let always_venv=1; let never_venv=0;;
    -N|--no-virtual-env) let always_venv=0; let never_venv=1;;
    -f|--force) let force=1;;
    -p|--pep8) let just_pep8=1;let never_venv=1; let always_venv=0;;
    -P|--no-pep8) no_pep8=1;;
    -l|--pylint) let just_pylint=1; let never_venv=1; let always_venv=0;;
    -c|--coverage) coverage=1;;
    -v|--verbose) verbose=1;;
    -*) noseopts="$noseopts $1";;
    *) noseargs="$noseargs $1"
  esac
}

venv=.venv
with_venv=tools/with_venv.sh
always_venv=0
never_venv=0
just_pep8=0
no_pep8=0
just_pylint=0
force=0
noseargs=
wrapper=""
coverage=0
verbose=0

for arg in "$@"; do
  process_option $arg
done

# If enabled, tell nose to collect coverage data
if [ $coverage -eq 1 ]; then
    noseopts="$noseopts --with-coverage --cover-package=quantum"
fi

function run_tests {
  for plugin_dir in ${PLUGIN_ARRAY[*]}
  do
    echo "Running core unit tests from "$plugin_dir
    echo "-----------------------------------------"
    CORE_ONLY=`[[ $plugin_dir == "." || $RUN_PLUGIN_TESTS ]] && echo "" || echo "--core_tests_only"`
    NOSETESTS="python ./$plugin_dir/run_tests.py $CORE_ONLY $noseopts $noseargs"
    if [ -n "$plugin_dir" ]
    then
      if ! [ -f ./$plugin_dir/run_tests.py ]
        then
  	      echo "Could not find run_tests.py in plugin directory $plugin_dir"
       	  exit 1
   	    fi
    fi

    if [ $verbose -eq 1 ]; then
      ${wrapper} $NOSETESTS
    else
      ${wrapper} $NOSETESTS 2> run_tests.log
    fi
    # If we get some short import error right away, print the error log directly
    RESULT=$?
    if [ "$RESULT" -ne "0" ];
    then
      ERRSIZE=`wc -l run_tests.log | awk '{print \$1}'`
      if [ $verbose -eq 0 -a "$ERRSIZE" -lt "40" ];
      then
        cat run_tests.log
      fi
      # stop in case of error
      return $RESULT
    fi
  done
}

function run_pylint {
  echo "Running pylint ..."
  PYLINT_OPTIONS="--rcfile=.pylintrc --output-format=parseable"
  PYLINT_INCLUDE="quantum"
  OLD_PYTHONPATH=$PYTHONPATH
  export PYTHONPATH=$PYTHONPATH:.quantum:./client/lib/quantum:./common/lib/quantum

  BASE_CMD="pylint $PYLINT_OPTIONS $PYLINT_INCLUDE"
  [ $verbose -eq 1 ] && $BASE_CMD || msg_count=`$BASE_CMD | grep 'quantum/' | wc -l`
  if [ $verbose -eq 0 ]; then
    echo "Pylint messages count: " $msg_count
  fi
  export PYTHONPATH=$OLD_PYTHONPATH
}

function run_pep8 {
  echo "Running pep8 ..."

  PEP8_EXCLUDE="vcsversion.py,*.pyc"
  # we now turn off pep8 1.3 E125 check to avoid make change to 
  # openstack-common . 
  PEP8_OPTIONS="--exclude=$PEP8_EXCLUDE --ignore=E125 --repeat --show-source"
  PEP8_INCLUDE="bin/* quantum run_tests.py setup*.py"
  ${wrapper} pep8 $PEP8_OPTIONS $PEP8_INCLUDE
}


if [ $never_venv -eq 0 ]
then
  # Remove the virtual environment if --force used
  if [ $force -eq 1 ]; then
    echo "Cleaning virtualenv..."
    rm -rf ${venv}
  fi
  if [ -e ${venv} ]; then
    wrapper="${with_venv}"
  else
    if [ $always_venv -eq 1 ]; then
      # Automatically install the virtualenv
      python tools/install_venv.py
      wrapper="${with_venv}"
    else
      echo -e "No virtual environment found...create one? (Y/n) \c"
      read use_ve
      if [ "x$use_ve" = "xY" -o "x$use_ve" = "x" -o "x$use_ve" = "xy" ]; then
        # Install the virtualenv and run the test suite in it
        python tools/install_venv.py
        wrapper=${with_venv}
      fi
    fi
  fi
fi

# Delete old coverage data from previous runs
if [ $coverage -eq 1 ]; then
    ${wrapper} coverage erase
fi

if [ $just_pep8 -eq 1 ]; then
    run_pep8
    exit
fi
if [ $just_pylint -eq 1 ]; then
    run_pylint
    exit
fi

RV=0
PLUGIN_PATH=${PLUGIN_PATH:-"./quantum/plugins/"}
PLUGINS=${PLUGINS:-"cisco linuxbridge metaplugin openvswitch nec nicira/nicira_nvp_plugin"}

if [[ -z $PLUGIN_DIR ]]; then
  PLUGIN_ARRAY=( $PLUGINS )
  # The '.' array item will cause to run tests against db_plugin
  PLUGIN_ARRAY=( "." `echo ${PLUGIN_ARRAY[@]/#/$PLUGIN_PATH}` )
else
  PLUGIN_ARRAY=( $PLUGIN_DIR )
  RUN_PLUGIN_TESTS=1
fi

if [ $no_pep8 -eq 1 ]; then
    run_tests
    RV=$?
else
    run_tests && run_pep8 || RV=1
fi

if [ $coverage -eq 1 ]; then
    echo "Generating coverage report in covhtml/"
    ${wrapper} coverage html -d covhtml -i
fi

exit $RV
