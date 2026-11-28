import { describe, expect, test } from 'bun:test'
import { shouldFollowAfterScroll, shouldUnpinForWheel } from './chatScrollPolicy.ts'

describe('native live transcript scrolling', () => {
  test('follows partial assistant content while reader remains at bottom', () => {
    expect(shouldFollowAfterScroll({
      top: 500, previousTop: 400, scrollHeight: 1000, clientHeight: 500,
      wasFollowing: true,
    })).toBe(true)
  })

  test('manual upward scroll always disables automatic bottom following', () => {
    expect(shouldUnpinForWheel(-120)).toBe(true)
    expect(shouldFollowAfterScroll({
      top: 400, previousTop: 540, scrollHeight: 1500, clientHeight: 500,
      wasFollowing: true,
    })).toBe(false)
  })

  test('content growth cannot re-pin a transcript the reader is reviewing', () => {
    expect(shouldFollowAfterScroll({
      top: 400, previousTop: 400, scrollHeight: 1800, clientHeight: 500,
      wasFollowing: false,
    })).toBe(false)
  })

  test('scrolling back near the bottom re-enables following', () => {
    expect(shouldFollowAfterScroll({
      top: 950, previousTop: 800, scrollHeight: 1500, clientHeight: 500,
      wasFollowing: false,
    })).toBe(true)
  })

  test('horizontal or downward wheel movement does not unpin', () => {
    expect(shouldUnpinForWheel(0)).toBe(false)
    expect(shouldUnpinForWheel(80)).toBe(false)
  })
})
