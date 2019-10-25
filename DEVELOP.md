# Find the source

[The source code is hosted on GitHub](https://github.com/msimerson/mail-dmarc)


# Download the source

To make changes or submit patches, visit the GitHub URL and click the ***Fork*** button. Then clone your fork to your local disk:

    git clone git@github.com:YOUR-USER-NAME/mail-dmarc.git


# Use the source

Use git in the normal way:

    cd mail-dmarc
    
    .... make a change or two ...
    git status       ( see changes )
    git diff         ( show diffs  )
    git add ...      ( stage changes )
    git commit

If your changes are significant and might possibly involve more than one commit, create a branch first:

    git checkout -b fix-knob-handle
    ... make changes ...
    git commit
    ... make more related changes ...
    git commit

When you are done making changes, push them to GitHub:

    git push origin     (push to your GitHub account)

When the new feature branch is no longer useful, delete it:

    git branch -d fix-knob-handle

# Submit your changes

    git push origin master    (push to your GitHub account)

Visit your fork on the GitHub web site. On the main page of your fork is a ***Pull Request*** button. That is how you submit your changes to the main repo. A collaborator will review your PR and either comment or merge it.

# Check build status:

[![Build Status](https://travis-ci.org/msimerson/mail-dmarc.png?branch=master)](https://travis-ci.org/msimerson/mail-dmarc)

Travis automatically runs build tests when commits are pushed to GitHub, and sends notifications to the author(s) in case of failure. For everyone else, checking the build status after a push request is merged is a good idea.

# Releases

Before a release, update the PSL:

````sh
curl -o share/public_suffix_list https://publicsuffix.org/list/effective_tld_names.dat
````
