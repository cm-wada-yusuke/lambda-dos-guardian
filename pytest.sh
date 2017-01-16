#!/bin/sh
cd $TRAVIS_BUILD_DIR/functions/attack-guardian-webapp && python main_spec.py -v
