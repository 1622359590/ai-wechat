#!/usr/bin/env python3
"""Run one command in a PTY and answer its two hidden password prompts."""

import errno
import os
import pty
import select
import signal
import sys
import time


def main() -> int:
    command = sys.argv[1:]
    if command[:1] == ["--"]:
        command = command[1:]
    answers = sys.stdin.buffer.read().splitlines()
    if not command or len(answers) != 2 or not all(answers):
        return 2

    child_pid, master_fd = pty.fork()
    if child_pid == 0:
        os.execvp(command[0], command)

    prompts = [b"Password: ", b"Repeat password: "]
    transcript = bytearray()
    sent = 0
    status = None
    deadline = time.monotonic() + 30
    try:
        while time.monotonic() < deadline:
            finished, child_status = os.waitpid(child_pid, os.WNOHANG)
            if finished == child_pid:
                status = child_status
                break
            readable, _, _ = select.select([master_fd], [], [], 0.25)
            if not readable:
                continue
            try:
                chunk = os.read(master_fd, 4096)
            except OSError as error:
                if error.errno == errno.EIO:
                    _, status = os.waitpid(child_pid, 0)
                    break
                raise
            if not chunk:
                _, status = os.waitpid(child_pid, 0)
                break
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
            transcript.extend(chunk)
            if sent < len(prompts) and prompts[sent] in transcript:
                os.write(master_fd, answers[sent] + b"\n")
                sent += 1
                transcript.clear()
        if status is None:
            os.kill(child_pid, signal.SIGTERM)
            _, status = os.waitpid(child_pid, 0)
            return 1
        return os.waitstatus_to_exitcode(status)
    finally:
        for answer in answers:
            del answer
        transcript.clear()
        os.close(master_fd)


if __name__ == "__main__":
    raise SystemExit(main())
