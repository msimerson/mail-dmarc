
# Find the source

[The source code is hosted on GitHub](https://github.com/msimerson/mail-dmarc)


# Download the source

To make changes or submit patches, visit the URL above and click the ***Fork*** button. Then clone your fork to your local disk with this git command:

    git clone git@github.com:YOUR-USER-NAME/mail-dmarc.git


# Use the source

Use git as one would with most any VCS:

    cd mail-dmarc
    
    .... make a little change or two ...
    git status       ( see changed files )
    git diff         ( show differences )
    git add          ( stage changes )
    git commit

If your changes are significant in any way, and/or might possibly involve more than one commit, create a branch:

    git checkout -b fix-knob-handle
    ... make changes ...
    git commit
    ... make more related changes ...
    git commit

When you are done with that branch, you can merge it back into the master branch:

    git checkout master
    git merge fix-knob-handle

When the branch is no longer useful, delete it:

    git branch -d fix-knob-handle

# Submit your changes

    git push origin master    (push to your GitHub account)

Visit your fork on the GitHub web site. On the main page of your fork is a ***Pull Request*** button. That is how you submit your changes to the main repo.

# Check Mail::DKIM build status:

[![Build Status](https://travis-ci.org/msimerson/mail-dmarc.png?branch=master)](https://travis-ci.org/msimerson/mail-dmarc)

Travis automatically runs build tests when commits are pushed to GitHub, and sends notifications to the author(s) in case of failure. For everyone else, checking the build status after a push request is merged is a good idea.
