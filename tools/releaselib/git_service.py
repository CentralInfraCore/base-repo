import subprocess
from .exceptions import GitServiceError

class GitService:
    """
    A service class to abstract Git command operations.
    This makes the core logic testable by allowing this service to be mocked.
    """
    def run(self, command):
        """
        Runs a Git command and returns its output, raising a GitServiceError on failure.
        """
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
                encoding='utf-8'
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            raise GitServiceError(f"Git command failed: {' '.join(command)}\n{e.stderr}")
        except FileNotFoundError:
            raise GitServiceError("Git command not found. Is Git installed and in your PATH?")

    def get_current_branch(self):
        """Returns the current active branch name."""
        return self.run(['git', 'rev-parse', '--abbrev-ref', 'HEAD'])

    def get_status_porcelain(self):
        """Returns the output of 'git status --porcelain'."""
        return self.run(['git', 'status', '--porcelain'])

    def get_tags(self, pattern=None):
        """Returns a list of tags, optionally filtered by a pattern."""
        command = ['git', 'tag', '--list']
        if pattern:
            command.append(pattern)
        
        raw_output = self.run(command)
        return raw_output.split('\n') if raw_output else []

    def write_tree(self):
        """Runs 'git write-tree' and returns the tree ID."""
        return self.run(['git', 'write-tree'])

    def add(self, file_path):
        """Stages a specific file."""
        return self.run(['git', 'add', file_path])
