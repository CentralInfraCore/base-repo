import subprocess
from .exceptions import GitServiceError

class GitService:
    """
    A service class to abstract Git command operations.
    This makes the core logic testable by allowing this service to be mocked.
    """
    def _run_raw(self, command):
        """Runs a command and returns raw stdout bytes."""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            raise GitServiceError(f"Git command failed: {' '.join(command)}\n{e.stderr.decode('utf-8', 'ignore')}")
        except FileNotFoundError:
            raise GitServiceError("Git command not found. Is Git installed and in your PATH?")

    def run(self, command):
        """
        Runs a Git command and returns its stripped string output.
        """
        raw_output = self._run_raw(command)
        return raw_output.decode('utf-8').strip()

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

    def archive_tree_bytes(self, tree_id):
        """
        Runs 'git archive' and returns the raw bytes of the tar archive.
        """
        return self._run_raw(['git', 'archive', '--format=tar', tree_id])
