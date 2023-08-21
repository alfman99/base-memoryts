/* eslint-disable no-console */
import test from 'ava'

import { is64BitProcess, isElevatedProcess, openProcessName, readByte } from '../index'

test('is node elevated?', (t) => {
  t.true(isElevatedProcess())
})

test('is 64 bits?', (t) => {
  t.true(is64BitProcess())
})

// test('list all processes on machine running', (t) => {
//   const processes = listProcesses()
//   t.true(processes.length > 0)
// })

// test('get handle of process explorer.exe', (t) => {
//   const processHandle = openProcessName('explorer.exe')
//   t.true(processHandle !== null)
// })

// test('get unexistant process test6test.exe', (t) => {
//   try {
//     openProcessName('test6test.exe')
//   } catch (e: any) {
//     t.true(e.code === 'Closing')
//   }
// })

test('read memory from Notepad.exe', (t) => {
  try {
    const handler = openProcessName('Notepad.exe')
    const character = String.fromCharCode(readByte(handler, 0x7ff8041d3930))
    t.true(character === 'X')
  } catch (e: any) {
    t.fail(e.message)
  }
})

// test('read memory from Notepad.exe', (t) => {
//   const buffer: number[] = []
//   try {
//     const handler = openProcessName('Notepad.exe')

//     const oldProtection = setProtection(handler, 0x25cd3863800, 4, 0x40)
//     write(handler, 0x25cd3863800, [4], 1)
//     setProtection(handler, 0x25cd3863800, 4, oldProtection)

//     console.log('buffer:', buffer)
//   } catch (e: any) {
//     console.error(e)
//   }
//   t.true(true)
// })

// test('dogshit loop open 1000 handles', (t) => {
//   const handles = []
//   for (let i = 0; i < 1000; i++) {
//     handles.push(openProcessName('explorer.exe'))
//   }
//   console.log('handles:', handles)
//   t.true(handles.length === 1000)
// })
