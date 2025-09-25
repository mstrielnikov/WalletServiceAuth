#!/bin/bash

docker build -t walletserviceauth . && docker run --rm -p 3000:3000 walletserviceauth

exit 0;