"""Private child for a fixed Git invocation from a pinned working-directory FD.

A separate process can fchdir safely without a threaded parent's preexec_fn.
This is not an agent-facing tool; the owner adapter supplies the descriptor and
sanitized temporary Git directory. It never accepts shell commands.
"""
import os
import sys


def main():
    descriptor = int(sys.argv[1])
    git_directory = sys.argv[2]
    os.fchdir(descriptor)
    os.close(descriptor)
    arguments = ["/usr/bin/git", "--no-pager", "--no-optional-locks", "--git-dir=" + git_directory, "--work-tree=.", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull, "-c", "core.untrackedCache=false", "status", "--porcelain=v1", "--untracked-files=no", "--ignore-submodules=all"]
    os.execve(arguments[0], arguments, dict(os.environ))


if __name__ == "__main__":
    main()
