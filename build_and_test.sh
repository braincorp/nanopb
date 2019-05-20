#  ============================================================================
#  Copyright 2019 BRAIN Corporation. All rights reserved. This software is
#  provided to you under BRAIN Corporation's Beta License Agreement and
#  your use of the software is governed by the terms of that Beta License
#  Agreement, found at http://www.braincorporation.com/betalicense.
#  ============================================================================

# Robust way of locating script folder
# from http://stackoverflow.com/questions/59895/can-a-bash-script-tell-what-directory-its-stored-in
SOURCE=${BASH_SOURCE:-$0}
DIR="$( dirname "$SOURCE" )"
while [ -h "$SOURCE" ]
do
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
  DIR="$( cd -P "$( dirname "$SOURCE"  )" && pwd )"
done
WDIR="$( pwd )"
DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

#set -e

cd $DIR/tests
scons #run the build/test suite
RETVAL=$?
echo; echo; echo;
if [ $RETVAL == "0" ]; then
    echo "Tests passed; nanopb is OK!"
else
    echo "Tests failed; nanopb is sad."
fi
echo; echo; echo;
scons -c #cleanup

cd $DIR
