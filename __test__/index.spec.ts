/* eslint-disable no-console */
import test from 'ava'

import {
  getModule,
  getProcessPid,
  is64BitProcess,
  isElevatedProcess,
  listAllRunningProcesses,
  listModules,
  openProcessName,
  readBuffer,
} from '../index'

test('is running elevated?', (t) => {
  t.true(isElevatedProcess())
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

test('list all modules from Notepad.exe', (t) => {
  try {
    const pid = getProcessPid('Notepad.exe')
    const modules = listModules(pid)
    t.true(modules.length > 0)
  } catch (e: any) {
    t.fail(e.message)
  }
})

test('read memory from Notepad.exe resolving static pointer', (t) => {
  try {
    const moduleInfo = getModule('Notepad.exe', 'textinputframework.dll')
    const offset = 0x133930

    const handler = openProcessName('Notepad.exe')
    const bufferRead = readBuffer(handler, moduleInfo.modBaseAddr + offset, 1)

    t.true(String.fromCharCode(bufferRead[0]) === 'X')
  } catch (e: any) {
    t.fail(e.message)
  }
})
