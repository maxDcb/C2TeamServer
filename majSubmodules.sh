cd core && git config --global --add safe.directory $(pwd) && git fetch && git rebase origin/master && cd -
cd libs/libDns && git config --global --add safe.directory $(pwd) && git fetch && git rebase origin/master && cd -
cd libs/libSocketHandler && git config --global --add safe.directory $(pwd) && git fetch && git rebase origin/master && cd -
cd libs/libSocks5 && git config --global --add safe.directory $(pwd) && git fetch && git rebase origin/master && cd -
cd thirdParty/donut && git config --global --add safe.directory $(pwd) && git fetch && git rebase origin/master && cd -

