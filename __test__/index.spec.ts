/* eslint-disable no-console */
import test from 'ava'

import {
  getProcessModules,
  is64BitProcess,
  isElevatedProcess,
  listAllRunningProcesses,
  openProcessName,
  readBuffer,
  writeBuffer,
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

test('read memory from Notepad.exe', (t) => {
  try {
    const handler = openProcessName('Notepad.exe')
    const bufferRead = readBuffer(handler, 0x7fff33db3930, 1)
    t.true(String.fromCharCode(bufferRead[0]) === 'X')
  } catch (e: any) {
    t.fail(e.message)
  }
})

test('write memory to Notepad.exe', (t) => {
  try {
    const handler = openProcessName('Notepad.exe')
    writeBuffer(handler, 0x7fff33db3930, [0x58, 0x00, 0x58, 0x00, 0x58, 0x00, 0x58, 0x00])
    t.pass()
  } catch (e: any) {
    t.fail(e.message)
  }
})

test('list all modules from Notepad.exe', (t) => {
  try {
    const handler = openProcessName('Notepad.exe')
    const modules = getProcessModules(handler)
    console.log(modules.map((m) => m.baseAddress))
    t.true(modules.length > 0)
  } catch (e: any) {
    t.fail(e.message)
  }
})
