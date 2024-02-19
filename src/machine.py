#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Machine abstraction for machine charms."""

import logging
import os
import subprocess
from typing import IO, AnyStr, Dict, Generic, Optional, Sequence, TextIO, Tuple

logger = logging.getLogger(__name__)


class ExecProcess(Generic[AnyStr]):
    """A class to represent a running process."""

    def __init__(
        self,
        stdin: Optional[IO[AnyStr]],
        stdout: Optional[IO[AnyStr]],
        stderr: Optional[IO[AnyStr]],
        timeout: Optional[float],
        command: Sequence[str],
        process: subprocess.Popen,
    ):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self._timeout = timeout
        self._command = command
        self._process = process

    def wait_output(self) -> Tuple[AnyStr, Optional[AnyStr]]:
        """Wait for the process to finish and return tuple of (stdout, stderr)."""
        try:
            stdout_data, stderr_data = self._process.communicate(timeout=self._timeout)
        except subprocess.TimeoutExpired:
            self._process.kill()
            stdout_data, stderr_data = self._process.communicate()
            raise TimeoutError(
                f"Command '{self._command}' timed out after {self._timeout} seconds"
            )

        exit_code = self._process.returncode
        if exit_code != 0:
            raise ExecError(self._command, exit_code, stdout_data, stderr_data)

        return stdout_data, stderr_data


class ExecError(Exception, Generic[AnyStr]):
    """A class to represent an error when executing a command."""

    def __init__(
        self,
        command: Sequence[str],
        exit_code: int,
        stdout: Optional[AnyStr],
        stderr: Optional[AnyStr],
    ):
        self.command = command
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


class Machine:
    """A class to interact with a unit machine.

    This class has the same method signatures as Pebble API in the Ops
    Library. This is to improve consistency between the Machine and Kubernetes
    versions of the charm.
    """

    def exists(self, path: str) -> bool:
        """Report whether a path exists on the filesystem.

        Args:
            path: The path

        Returns:
            bool: Whether the path exists
        """
        return os.path.exists(path)

    def pull(self, path: str) -> str:
        """Get the content of a file.

        Args:
            path: The path of the file

        Returns:
            str: The content of the file
        """
        with open(path, "r") as read_file:
            return read_file.read()

    def push(self, path: str, source: str) -> None:
        """Pushes a file to the unit.

        Args:
            path: The path of the file
            source: The contents of the file to be pushed
        """
        with open(path, "w") as write_file:
            write_file.write(source)
            logger.info("Pushed file %s", path)

    def exec(
        self,
        command: Sequence[str],
        environment: Optional[Dict[str, str]] = None,
        working_dir: Optional[str] = None,
        timeout: Optional[float] = None,
        user: Optional[str] = None,
        group: Optional[str] = None,
        stdin: Optional[TextIO] = None,
        stdout: Optional[TextIO] = None,
        stderr: Optional[TextIO] = None,
    ) -> ExecProcess:
        """Execute a command on the machine.

        Args:
            command: The command to execute
            environment: The environment variables to set
            working_dir: The working directory to execute the command in
            timeout: The timeout for the command
            user: The user to execute the command as
            group: The group to execute the command as
            stdin: The standard input for the command
            stdout: The standard output for the command
            stderr: The standard error for the command
        """
        process = subprocess.Popen(
            args=command,
            stdin=stdin,
            stdout=subprocess.PIPE if stdout is None else stdout,
            stderr=subprocess.PIPE if stderr is None else stderr,
            shell=True,
            cwd=working_dir,
            env=environment,
            user=user,
            group=group,
            text=True,
        )
        return ExecProcess(
            stdin=stdin,
            stdout=process.stdout,
            stderr=process.stderr,
            timeout=timeout,
            command=command,
            process=process,
        )
