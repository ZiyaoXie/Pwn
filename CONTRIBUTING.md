# Contributing

First off, thank you for considering contributing to Pwn. It's people like you that make this project such a great tool.

## Where do I go from here?

If you've noticed a bug or are interested in a write-up, [make a new issue][new issue]! It's generally best if you get confirmation of your bug or approval for your feature
request this way before starting to code.

## Fork & create a branch

If this is something you think you can fix, then [fork Pwn] and create a branch with a descriptive name.

A good branch name would be (where issue #325 is the ticket you're working on):

```sh
git checkout -b 325-add-writeup-for-xxx
```

## A simple template

This is a [template](template/README.md) for write-ups.

## Make a Pull Request

At this point, you should switch back to your main branch and make sure it's up to date with Pwn's main branch:

```sh
git remote add upstream https://github.com/ZiyaoXie/Pwn.git
git checkout main
git pull upstream main
```

Then update your branch from your local copy of main, and push it!

```sh
git checkout 325-add-writeup-for-xxx
git rebase main
git push --set-upstream origin 325-add-writeup-for-xxx
```

Finally, go to GitHub and [make a Pull Request][] :D

Generally your PR won't be merged until more than one person has reviewed your code.

## Keeping your Pull Request updated

If a maintainer asks you to "rebase" your PR, they're saying that a lot of code has changed, and that you need to update your branch so it's easier to merge.

To learn more about rebasing in Git, there are a lot of [good][git rebasing] [resources][interactive rebase] but here's the suggested workflow:

```sh
git checkout 325-add-writeup-for-xxx
git pull --rebase upstream main
git push --force-with-lease 325-add-writeup-for-xxx
```

## Merging a PR (maintainers only)

A PR can only be merged into master by a maintainer if:

* It has been approved by at least two maintainers. If it was a maintainer who opened the PR, only one extra approval is needed.
* It has no requested changes.
* It is up to date with current master.

Any maintainer is allowed to merge a PR if all of these conditions are met.

[new issue]: https://github.com/ZiyaoXie/Pwn/issues/new
[fork Pwn]: https://help.github.com/articles/fork-a-repo
[make a pull request]: https://help.github.com/articles/creating-a-pull-request
[git rebasing]: http://git-scm.com/book/en/Git-Branching-Rebasing
[interactive rebase]: https://help.github.com/en/github/using-git/about-git-rebase
