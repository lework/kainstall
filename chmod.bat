git config core.filemode false
git update-index --chmod=+x kainstall-centos.sh
git update-index --chmod=+x kainstall-debian.sh
git ls-files --stage
timeout /nobreak /t 5