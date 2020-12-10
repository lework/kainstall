git config core.filemode false
git update-index --chmod=+x kainstall.sh
git ls-files --stage
timeout /nobreak /t 5