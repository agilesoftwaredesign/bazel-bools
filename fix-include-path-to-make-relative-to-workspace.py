#!/usr/bin/env python3
"""
run test with e.g. python3 -m unittest fix-include-path-to-make-relative-to-workspace.BazelUtilTest
"""
import os
import sys
import json
import unittest
import argparse
import re
import logging

IGNORE_INCLUDES = ['cstdint', 'map', 'vector', 'string', 'memory', 'unordered_map', 'stdexcept', 'set', 'queue',
                   'limits', 'sstream', 'numeric', 'tuple', 'array']  # for speed-up and tweaking
KEEP_AFTER_INCLUDE_PREFIX = ['k8-opt/bin/external']
K8OUT = 'bazel-out/k8-opt/bin/'
INCLUDE_SUFFIXES = ('.h', '.hpp')
PROCESS_ONLY_FILE_SUFFIX = ('.h', '.hpp', '.c', '.cpp', '.hh', '.cc')
INCL_REGEX_A = re.compile(r'\s*includes\s*=\s*\[')
STRIP_INCL_REGEX_A = re.compile(r'\s*strip_include_prefix\s*=\s*\[')
INCL_PREFIX_REGEX_A = re.compile(r'\s*include_prefix\s*=\s*\[')
INCL_REGEX_B = re.compile(r'\s*includes\s*=')
STRIP_INCL_REGEX_B = re.compile(r'\s*strip_include_prefix\s*=')
INCL_PREFIX_REGEX_B = re.compile(r'\s*include_prefix\s*=')
CLOSE_REGEX = re.compile(r'.*]\s*,')

LOGGER = logging.getLogger('fix-include-path')
logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.ERROR)


class BazelPackageName:
    def __init__(self, name):
        assert (name.startswith('//'))
        assert (name.find(':') == -1)
        # assert (name.find('.') == -1)
        self.name = name

    @staticmethod
    def make_from_directory(directory):
        if not os.path.exists(directory) or not os.path.isdir(directory):
            raise Exception('folder does not exist')
        build_file_short = os.path.join(directory, "BUILD")
        build_file_long = os.path.join(directory, "BUILD.bazel")
        if os.path.exists(build_file_short) or os.path.exists(build_file_long):
            return BazelPackageName("//" + directory)
        else:
            raise Exception('cannot make bazel package from non-bazel package folder')

    def stripped_package_name(self) -> str:
        return self.name[2:]

    def folder(self):
        return os.path.join(os.path.abspath(os.curdir), self.name[2:])

    def buildfile(self):
        build_file_short = os.path.join(self.folder(), "BUILD")
        build_file_long = os.path.join(self.folder(), "BUILD.bazel")
        if os.path.exists(build_file_short):
            return build_file_short
        elif os.path.exists(build_file_long):
            return build_file_long
        else:
            raise Exception('cannot provide BUILD file')


class BazelPackageProcessor:
    def __init__(self, build_package: BazelPackageName) -> None:
        self.build_package = build_package

    def process(self):
        compile_command_files = Util.get_compile_commands_of_package(self.build_package)
        for bazel_target_compile_command_file in compile_command_files:
            LOGGER.debug(
                'process in bazel package ' + self.build_package.stripped_package_name() +
                ' the compile command file: ' + bazel_target_compile_command_file)
            p = BazelTargetProcessor(bazel_target_compile_command_file)
            p.process()

    def modify_build(self):
        with open(self.build_package.buildfile(), 'r') as fi:
            build_content = fi.readlines()
            new_content = Util.modify_build(build_content)
            with open(self.build_package.buildfile() + '-', 'w') as fo:
                for new_content_line in new_content:
                    fo.write(new_content_line)
        os.replace(self.build_package.buildfile() + '-', self.build_package.buildfile())
        # self.make_consistent_changes_to_dependent_files()

    def make_consistent_changes_to_dependent_files(self):
        for dependent_file in self.determine_dependent_files():
            self.fix_includes(dependent_file)

    def determine_dependent_files(self):
        BazelUtil.dependent_source_files_on_bazel_package_NOT_WORKING(self.build_package)


class BazelTargetProcessor:
    def __init__(self, compile_command_file):
        self.file_candidates = None
        self.file_lookup_cache = None
        self.compile_command_file = compile_command_file

    def process(self):
        for j in self.compile_command_lines():
            self.process_file(j['file'])

    def process_file(self, filename):
        if not filename.endswith(PROCESS_ONLY_FILE_SUFFIX):
            print('+ skipping ' + filename)
            return
        if not os.path.exists(filename):
            print('+ skip not existing file ' + filename)
            return

        print('+ process: ' + filename)
        temporary_filename = filename + '-'
        # TODO need to shift this currently_processed_file into a context-like structure
        self.currently_processed_file = filename
        with open(filename, 'r') as fi:
            new_content = Util.modify_include(fi.readlines(), self._file_lookup)
            with open(temporary_filename, 'w') as fo:
                for line in new_content:
                    fo.write(line)
        os.replace(temporary_filename, filename)

    def make_consistent_changes_to_dependent_files(self):
        raise Exception('not yet implemented')

    def _assure_file_lookup_cache_is_initialized(self):
        if self.file_lookup_cache is not None:
            return
        list_of_folders_to_search_through = []
        for j in self.compile_command_lines():
            opts = Util.extract_include_path_manipulation_option(j['command'])
            incl_paths = Util.incl_options_to_paths(opts)
            # we need to preserve order of directories, therefore no set()
            for folder in incl_paths:
                if folder not in list_of_folders_to_search_through:
                    list_of_folders_to_search_through.append(folder)
        of_all = self.list_of_all(list_of_folders_to_search_through)

        # as start of python 3.7 dictonary is garateed to keep order
        # (https://mail.python.org/pipermail/python-dev/2017-December/151283.html and https://stackoverflow.com/a/7961390)
        self.file_lookup_cache = list(dict.fromkeys(of_all))
        LOGGER.info(f'cache with {len(self.file_lookup_cache)} items')

    def _file_lookup(self, for_file):
        LOGGER.debug(f'file lookup for "{for_file}" within context of {self.currently_processed_file}')
        self._assure_file_lookup_cache_is_initialized()
        cand = [x for x in self.file_lookup_cache if x.endswith(for_file)]
        if len(cand) != 1:
            LOGGER.warning(
                'there are multiple (or none) possibilities to resolve "{}" given '
                'the context of {} with the compile_command file {}. '
                'See (#{}): {}'.format(
                    for_file,
                    self.currently_processed_file,
                    self.compile_command_file,
                    str(len(cand)),
                    str(cand)))
        if len(cand) == 1 and cand[0] == for_file:
            return None
        if len(cand) > 0:
            # take first, this is std-complaint
            return cand[0]
        else:
            # no candidate found
            return None

    def compile_command_lines(self):
        assert self.compile_command_file, 'bazel target compile file required'
        with open(self.compile_command_file, 'r') as cf:
            line_from_compile_command = cf.readline().strip()
            while line_from_compile_command:
                if line_from_compile_command[-1] == ',':
                    line_from_compile_command = line_from_compile_command[0:-1]
                j = json.loads(line_from_compile_command)
                yield j
                line_from_compile_command = cf.readline().strip()

    @staticmethod
    def list_of_all(incl_paths):
        candidates = []
        for path in incl_paths:
            if path == 'bazel-out/k8-opt/bin':
                # print(' false performance short cut')
                continue
            # by using grep, we cover also the "with path" for_file case
            include_suffix_find_command = '-name ' + ' -o -name '.join(['"*' + i + '"' for i in INCLUDE_SUFFIXES])
            cmd = f'find "{path}" {include_suffix_find_command} 2>/dev/null'
            with os.popen(cmd) as cmd_process:
                x = cmd_process.readlines()
            candidates.extend(x)
        cand_set = []
        for c in candidates:
            real_path_candidate = os.path.realpath(c.strip())
            stripped = Util.strip_non_workspace_relative_prefix(real_path_candidate)
            cand_set.append(stripped)
        return cand_set


class BazelUtil:
    @staticmethod
    def all_packages():
        with os.popen(
                'find . -name BUILD -o -name BUILD.bazel | rev | cut -d/ -f 2- | rev | cut -c3- | uniq') as cmd_process:
            x = cmd_process.readlines()
        return x

    @staticmethod
    def all_files_in_package(bazel_package):
        cmd = 'bazel query \'kind("source file", deps({}))\' 2>/dev/null | grep -v \'^@\''.format(
            bazel_package)
        with os.popen(cmd) as cmd_process:
            x = cmd_process.readlines()
        return [BazelFileTarget(f.strip()) for f in x if len(f) > 1]

    @staticmethod
    def dependent_source_files_on_bazel_package_NOT_WORKING(bazel_package):
        # due to permission issues, this command cannot be tested
        cmd = 'bazel query \'kind("source file", rdeps(..., {}))\' 2>/dev/null'.format(
            bazel_package)
        with os.popen(cmd) as cmd_process:
            x = cmd_process.readlines()
        return [BazelFileTarget(f.strip()) for f in x if len(f) > 1]


class BazelFileTarget:
    def __init__(self, description):
        self.description = description.strip()

    def get_workspace_related_file(self):
        if self.description[0] == '@':
            raise Exception('not supported for external files')
        sp = self.description.split(':')
        return os.path.join(sp[0][2:], sp[1])

    def __str__(self):
        return self.description

    def __eq__(self, other):
        return str(other) == str(self)


class Util:
    @staticmethod
    def is_include_line(full_include_line):
        return full_include_line.startswith('#include')

    @staticmethod
    def extract_include_subject(full_include_line):
        if not Util.is_include_line(full_include_line):
            return None
        open_bracket_pos = full_include_line.find('<')
        close_bracket_pos = full_include_line.find('>')
        if 0 < open_bracket_pos < close_bracket_pos:
            return full_include_line[open_bracket_pos + 1: close_bracket_pos]
        first_quote = full_include_line.find('"')
        second_quote = full_include_line.find('"', first_quote + 1)
        if 0 < first_quote < second_quote:
            return full_include_line[first_quote + 1: second_quote]
        return None

    @staticmethod
    def next_include_option(arg, startpos):
        a = arg.find('-I ', startpos)
        b = arg.find('-isystem', startpos)
        pos = -1
        if a > 0 and b > 0:
            pos = min(a, b)
        elif a > 0:
            pos = a
        elif b > 0:
            pos = b
        return pos

    @staticmethod
    def extract_include_path_manipulation_option(arg):
        opts = []
        pos = Util.next_include_option(arg, 0)
        while pos > 0:
            nextspace = arg.index(' ', pos)
            overnextspace = arg.index(' ', nextspace + 1)
            snip = arg[pos: overnextspace]
            opts.append(snip)
            pos = Util.next_include_option(arg, pos + len(snip))
        return opts

    @staticmethod
    def strip_non_workspace_relative_prefix(path):
        for ignore in KEEP_AFTER_INCLUDE_PREFIX:
            pos = path.find(ignore)
            if pos > -1:
                return path[pos + len(ignore) + 1:]

        workspace_abs_path = os.path.abspath('.')
        if path.startswith(workspace_abs_path):
            return path[len(workspace_abs_path) + 1:]
        else:
            return path[path.index(K8OUT) + len(K8OUT):]

    @staticmethod
    def get_compile_commands_of_package(bazel_package: BazelPackageName, find_result=None):
        path = K8OUT + bazel_package.stripped_package_name()
        LOGGER.debug('searching for compile commands of package ' + bazel_package.stripped_package_name())
        if not find_result:
            find_result = os.popen(
                'find ' + path + ' -name \'*.compile_commands.json\' 2>/dev/null').read()
        compile_command_files = [x for x in find_result.split('\n') if len(x) > 0]
        LOGGER.debug(
            'package ' + bazel_package.stripped_package_name() + ' does have ' + str(
                len(compile_command_files)) + ' compile command files')
        if len(compile_command_files) <= 0:
            LOGGER.warning('no compile commands found for package ' + bazel_package.stripped_package_name())
            print(
                '  no compile commands found for package ' + bazel_package.stripped_package_name() +
                ' . So no include fixing on this package')
            return []
        return compile_command_files

    @staticmethod
    def incl_options_to_paths(opts):
        paths = []
        for p in opts:
            path = p[p.index(' ') + 1:]
            paths.append(path)
        return paths

    @staticmethod
    def modify_include(content, file_lookup):
        assert (isinstance(content, list))
        outline = []
        for line_of_content in content:
            include_subj = Util.extract_include_subject(line_of_content)
            if not include_subj:
                outline.append(line_of_content)
            elif include_subj in IGNORE_INCLUDES:
                outline.append(line_of_content)
            else:
                ws_relative_incl_subj = file_lookup(include_subj)
                if not ws_relative_incl_subj:
                    outline.append(line_of_content)
                else:
                    line_end = line_of_content[-1:]
                    if ord(line_end) >= ord('"'):
                        line_end = ''
                    outline.append('#include "' + ws_relative_incl_subj + '"' + line_end)
        return outline

    @staticmethod
    def modify_build(content):
        assert (isinstance(content, list))
        outline = []
        skip_line = False
        skip_multi_line = False
        for line_in_build_file in content:
            if INCL_REGEX_A.match(line_in_build_file) or INCL_PREFIX_REGEX_A.match(
                    line_in_build_file) or STRIP_INCL_REGEX_A.match(line_in_build_file):
                # array like argument
                skip_multi_line = True
            elif INCL_REGEX_B.match(line_in_build_file) or INCL_PREFIX_REGEX_B.match(
                    line_in_build_file) or STRIP_INCL_REGEX_B.match(line_in_build_file):
                # line like argument
                skip_line = True

            if not skip_line and not skip_multi_line:
                outline.append(line_in_build_file)

            # close of skipping
            if skip_multi_line and CLOSE_REGEX.match(line_in_build_file):
                skip_multi_line = False
            if skip_line:
                skip_line = False
        return outline


class TestUtil(unittest.TestCase):
    def test_is_include_line(self):
        self.assertTrue(Util.is_include_line('#include "foo"'))
        self.assertFalse(Util.is_include_line(' #include "foo"'))

    def test_extract_include_subject(self):
        self.assertEqual(Util.extract_include_subject('#include "foo.h"'), 'foo.h')
        self.assertEqual(Util.extract_include_subject('#include <foo-bar.h>'), 'foo-bar.h')
        self.assertEqual(Util.extract_include_subject('#include <foo-bar-wired.h"'), None)
        self.assertEqual(Util.extract_include_subject('// #include <foo-bar-wired.h>'), None)
        # self.assertEqual(Util.extract_include_subject('#include ""'), None)
        # self.assertEqual(Util.extract_include_subject('#include <>'), None)
        self.assertEqual(Util.extract_include_subject('#incl'), None)

    def test_include_path_manipulation_option(self):
        arg = '/usr/bin/gcc -U_FORTIFY_SOURCE -Wformat-security -fno-canonical-system-headers -Wno-builtin-macro-redefined -D__DATE__=\"redacted\" -D__TIMESTAMP__=\"redacted\" -D__TIME__=\"redacted\" -I bazel-out/k8-opt/bin/folder01 -I bazel-out/k8-opt/bin/folder_bla -Iquote . -Iquote bazel-out/k8-opt/bin -x c++ -c foo/bla/intra.cpp'
        exp = ['-I bazel-out/k8-opt/bin/folder01', '-I bazel-out/k8-opt/bin/folder_bla']
        self.assertEqual(Util.extract_include_path_manipulation_option(arg), exp)

    def test_incl_options_to_paths(self):
        inp = ['-I folder01', '-isystem folder02']
        exp = ['folder01', 'folder02']
        self.assertListEqual(Util.incl_options_to_paths(inp), exp)

    def test_get_compile_commands_of_package(self):
        find_result = 'communication_integration_test.compile_commands.json\n' \
                      'calibration_integration_test.compile_commands.json\n' \
                      'integration_test_support.compile_commands.json'
        p = Util.get_compile_commands_of_package(BazelPackageName('//package_name/non-sense'), find_result)
        self.assertEqual(len(p), 3)

    def test_strip_non_workspace_relative_prefix_with_inner_include(self):
        self.assertEqual(Util.strip_non_workspace_relative_prefix(
            K8OUT + '/doesnt/matter/for/unittest/x.h'),
            '/doesnt/matter/for/unittest/x.h')

    def test_strip_non_workspace_relative_prefix_with_external_include(self):
        self.assertEqual(Util.strip_non_workspace_relative_prefix(
            'e4d8e59c42434412bb5407aba53873b2/execroot/ddad/bazel-out/k8-opt/bin/external/std_msgs_archive/std_msgs/UInt64MultiArray.h'),
            'std_msgs_archive/std_msgs/UInt64MultiArray.h')

    def test_modify_build_array(self):
        cont = """   includes = [
   "x"
],
first,
  strip_include_prefix = [
  "dd"
],
second,
  include_prefix = [
   "sdsd"
],
third"""
        self.assertListEqual(Util.modify_build(cont.split('\n')), ['first,', 'second,', 'third'])

    def test_modify_include(self):
        cont = """///
#include <map>
#include "foo.h"

sdad"""
        mocked_lookup = lambda x: 'application/foo.h' if x == 'foo.h' else None
        x = Util.modify_include(cont.split('\n'), mocked_lookup)
        self.assertListEqual(x, """///
#include <map>
#include "application/foo.h"

sdad""".split('\n'))


class BazelUtilTest(unittest.TestCase):
    def ignore_test_all_files_in_package(self):
        x = BazelUtil.all_files_in_package('//myapp/in/component/common/algorithm/test:all')
        self.assertListEqual(['//myapp/in/component/common/algorithm/test:algorithm_unit_test.cpp',
                              '//myapp/in/component/common/algorithm:algorithm.h',
                              '//myapp/in/component/common/algorithm:algorithm.cpp'], x)


class BazelFileTargetTest(unittest.TestCase):
    def test_get_workspace_related_file(self):
        x = BazelFileTarget('//myapp/in/component/common/algorithm:algorithm.cpp')
        self.assertEqual('myapp/in/component/common/algorithm/algorithm.cpp', x.get_workspace_related_file())

    def test_no_external(self):
        x = BazelFileTarget('@bazel_tools//src/tools/launcher:launcher.h')
        self.assertRaises(Exception, x.get_workspace_related_file)


class BazelPackageNameTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(BazelPackageNameTest, self).__init__(*args, **kwargs)
        self.sample_bazel_package_name = None

    def ignore_test0(self):
        if self.sample_bazel_package_name is None:
            return
        x = BazelPackageName('//' + self.sample_bazel_package_name)
        path = x.folder()
        self.assertTrue(path.startswith('/'), 'start at FS root')
        self.assertTrue(path.endswith(self.sample_bazel_package_name),
                        'ends with package name, no BUILD or anything else')

    def ignore_test1(self):
        if self.sample_bazel_package_name is None:
            return
        x = BazelPackageName('//' + self.sample_bazel_package_name)
        self.assertTrue(x.buildfile().endswith('BUILD'), 'BUILD file')

    def ignore_test2(self):
        if self.sample_bazel_package_name is None:
            return
        x = BazelPackageName.make_from_directory(self.sample_bazel_package_name)
        self.assertEqual(self.sample_bazel_package_name, x.stripped_package_name())
        self.assertFalse(x.stripped_package_name().startswith('/'), 'no abs path')


def process_package(bazel_package, arguments):
    bazel_package = bazel_package.strip()
    if bazel_package is None or bazel_package == '' or bazel_package.find('@') >= 0:
        print('skip package', bazel_package)
        return
    bazel_package = BazelPackageName('//' + bazel_package)
    print('process package', bazel_package.stripped_package_name())
    p = BazelPackageProcessor(bazel_package)
    if not arguments.no_fix_includes:
        p.process()
    if not arguments.no_remove_modifiers:
        p.modify_build()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Make include paths in CPP and H files bazel-community complaint')
    parser.add_argument('bazeltarget', nargs='*', type=str, help='target')
    parser.add_argument('--no_remove_modifiers', action="store_true",
                        help='don\'t remove include path modifiers from build file')
    parser.add_argument('--no_fix_includes', action="store_true", help='don\'t fix include paths in files')
    parser.add_argument('--pipe', action="store_true", help='read package names from STDIN')
    parser.add_argument('--allpackages', action="store_true", help='process all bazel packages')
    parser.add_argument('--log', help='set log level')
    # parser.add_argument('--compilecommands', help='compile commands of all packages in one JSON',
    #                    default='./compile_commands.json')
    args = parser.parse_args()

    if len(args.bazeltarget) == 0 and not args.pipe and not args.allpackages:
        parser.print_help()
        sys.exit(1)
    assert (os.path.exists('WORKSPACE'))

    if args.log:
        numeric_level = getattr(logging, args.log.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % args.log)
        logging.getLogger('').setLevel(numeric_level)

    if args.pipe:
        for line in sys.stdin:
            process_package(line, args)
    elif args.allpackages:
        for package in BazelUtil.all_packages():
            process_package(package, args)
    else:
        for package in args.bazeltarget:
            process_package(package, args)
