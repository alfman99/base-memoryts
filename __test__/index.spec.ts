/* eslint-disable no-console */
import test from 'ava'

import {
  getProcessPid,
  is64BitProcess,
  isElevatedProcess,
  isProcessX64,
  listAllRunningProcesses,
  listProcessModules,
  openProcessName,
} from '..'

test('is running elevated?', (t) => {
  t.false(isElevatedProcess())
})

test('is 64 bits?', (t) => {
  t.true(is64BitProcess())
})

test('list all processes on machine running', (t) => {
  const processes = listAllRunningProcesses()
  t.true(processes.length > 0)
})

test('get handle of process explorer.exe', (t) => {
  const processHandle = openProcessName('explorer.exe')
  t.true(processHandle !== null)
})

test('get unexistant process test6test.exe', (t) => {
  try {
    openProcessName('test6test.exe')
  } catch (e: any) {
    t.true(e.code === 'Closing')
  }
})

test('is target x64?', (t) => {
  const processHandle = openProcessName('explorer.exe')
  t.true(processHandle !== null)
  if (processHandle) {
    t.true(isProcessX64(processHandle))
  }
})

test('get process module list', (t) => {
  const pid = getProcessPid('explorer.exe')
  t.true(pid !== null)
  if (pid) {
    const modules = listProcessModules(pid)
    t.true(modules.length > 0)
  }
})
