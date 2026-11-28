/** Browser-native conversation scroll anchoring.
 *  The reader controls whether new streamed content may move the viewport.
 *  A scroll away from the bottom always wins over automatic growth following.
 */
export interface ScrollPosition {
  top: number
  previousTop: number
  scrollHeight: number
  clientHeight: number
  stickThreshold?: number
  wasFollowing: boolean
}

export function shouldFollowAfterScroll(position: ScrollPosition): boolean {
  const { top, previousTop, scrollHeight, clientHeight, wasFollowing } = position
  const threshold = position.stickThreshold ?? 80
  const remaining = scrollHeight - top - clientHeight
  if (remaining <= threshold) return true
  if (top < previousTop - 1) return false
  return wasFollowing
}

export function shouldUnpinForWheel(deltaY: number): boolean {
  return deltaY < 0
}
