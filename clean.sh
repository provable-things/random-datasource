#!/bin/bash

find . -name "*.pyc" -exec rm {} \;
find . -name "*.hex" -exec rm {} \;
find . -name "*.log" -exec rm {} \;
find . -name "*.bin" -exec rm {} \;
find . -name "keystore.db" -exec rm -r {} \;
