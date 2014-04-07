#!/bin/sh
if [ -z $1 ]; then
    echo "ERROR: Argument missing!"
    echo "Usage: ./tag.sh v1.1.1"
    exit
fi

git tag $1
git push --tags
