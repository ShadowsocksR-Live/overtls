#!/bin/sh
/command/s6-svstat /run/s6-rc/servicedirs/caddy || exit 1
/command/s6-svstat /run/s6-rc/servicedirs/overtls || exit 1