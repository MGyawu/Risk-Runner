#!/bin/bash
# EC2 user data (paste into "Advanced details > User data" when launching Ubuntu 24.04).
# Installs Docker and the AWS CLI. The SSM agent is preinstalled on Ubuntu AMIs.
set -eux
curl -fsSL https://get.docker.com | sh
usermod -aG docker ubuntu
snap install aws-cli --classic
