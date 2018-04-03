###############################################################################
# Hg credentials
###############################################################################

# Git credentials
Set-Environment "EMAIL" "Igor Frunze <madm.pro@gmail.com>"
Set-Environment "GIT_AUTHOR_NAME" "Igor Frunze","User"
Set-Environment "GIT_COMMITTER_NAME" $env:GIT_AUTHOR_NAME
git config --global user.name $env:GIT_AUTHOR_NAME
Set-Environment "GIT_AUTHOR_EMAIL" "madm.pro@gmail.com"
Set-Environment "GIT_COMMITTER_EMAIL" $env:GIT_AUTHOR_EMAIL
git config --global user.email $env:GIT_AUTHOR_EMAIL
