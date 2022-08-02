#!/usr/bin/env python
"""
This is a set of helper functions for system utilities
"""

from subprocess import Popen, PIPE, call
import plistlib
from re import IGNORECASE
from re import compile as recompile
from os.path import isfile, split


def shell_out(command):
    """
    Executes a shell command and returns it's output as an array of lines

    Arguments
      - command: the full command to be executed
    """
    return Popen(
        command.split(' '),
        stdout=PIPE,
        stderr=PIPE
    ).communicate()[0].strip('\n').split('\n')


def get_kextstat():
    """
    Returns a nice JSON array of `kextstat`
    """
    kextstat = shell_out("kextstat -l")
    header = [
        'Index',
        'Refs',
        'Address',
        'Size',
        'Wired',
        'Name',
        'Version',
        'Linked Against'
    ]
    kextstat_json = {}
    for i in range(len(kextstat)):
        mod = filter(None, kextstat[i].split(" "))
        mod = mod[:7] + ["-".join(mod[7:])]
        kextstat[i] = mod

    for i in kextstat:
        j = dict(zip(header, i))
        kextstat_json[j["Index"]] = j

    return kextstat_json


def get_kextfind():
    """
    Returns an array of .kext files
    """
    return kextfind if (kextfind := shell_out("kextfind")) else None


def get_launchctl():
    """
    Returns a nice JSON array of `launchctl list`
    """
    launchctl = shell_out("/bin/launchctl list")
    header = ["PID", "Status", "Label"]
    launchctl_json = {}

    launchctl = launchctl[1::]

    for i in range(len(launchctl)):
        mod = filter(None, launchctl[i].split("\t"))
        launchctl[i] = mod

    for i in range(len(launchctl)):
        j = dict(zip(header, launchctl[i]))
        launchctl_json[i] = j

    return launchctl_json


def strings(executable):
    """
    Returns an array of unique strings found in a supplied executable
    """
    if not isfile(executable):
        return []
    try:
        strings_list = list(set(shell_out(f"strings {executable}")))
    except Exception:
        return []
    return strings_list or []


def delete_file(filename):
    """
    Calls "rm" on a supplied file
    """
    call(["rm", "-f", filename])


def installed(program):
    """
    Returns the path of a supplied program if the supplied program is installed
    and returns False if it is not
    """
    if not (which := shell_out(f"mdfind -name {program}")):
        return False
    for i in which:
        _, fname = split(i)
        if fname == program:
            return i


def last_user_name():
    """
    Returns the last logged in username from com.apple.loginwindow.plist
    """
    command = " ".join([
        "defaults",
        "read",
        "/Library/Preferences/com.apple.loginwindow.plist",
        "lastUserName",
    ])
    last_user = shell_out(command)
    if len(last_user) != 1:
        return False
    else:
        last_user = last_user[0]
    return last_user


def crontab_for_user(user):
    """
    Returns False is a supplied user doesn't have a crontab, and returns the
    crontab (pipes in place of newlines) if the user does have one
    """
    if crontab := filter(None, shell_out(f"crontab -u {user} -l")):
        return '|'.join(crontab)
    else:
        return False


def last():
    """
    Returns the first two columns of the `last` command
    """
    last_command = shell_out("last")[:-2]
    return [filter(None, i.split(" "))[:2] for i in last_command]


def list_users():
    """
    Returns an array of all 'users' on the system
    """
    users = []
    if dscacheutil := shell_out("dscacheutil -q user"):
        users.extend(i[6:] for i in dscacheutil if i.startswith('name: '))
    return users


def run_file(filename):
    """
    Returns file information on a given filename. Returns None if file doesn't
    exist
    """
    if not isfile(filename):
        return
    output = shell_out(f"file {filename}")
    if output:
        try:
            output = output[0]
        except OSError:
            return None
        except:
            return None
    return output or None


def lsof():
    """
    Returns a array of lsof -i data
    """
    lsof_output = shell_out("lsof -i")
    headers = [
        'command',
        'pid',
        'user',
        'fd',
        'type',
        'device',
        'size/off',
        'node',
        'name',
    ]
    lsof_output = lsof_output[1:]

    return [dict(zip(headers, filter(None, i.split(" ")))) for i in lsof_output]


def is_fde_enabled():
    """
    Returns True if FDE is enabled, False if it is not
    """
    fde = shell_out("fdesetup status")
    return fde == ['FileVault is On.']
