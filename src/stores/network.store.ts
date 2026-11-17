import { create } from "zustand"

type NetworkState = {
  /** Internet reachability as probed by the Rust side (connectivity.rs). */
  online: boolean
  /** Epoch ms of the last change, for "offline for 2m" style hints. */
  since: number
  setOnline: (online: boolean) => void
}

export const useNetworkStore = create<NetworkState>((set, get) => ({
  online: true,
  since: Date.now(),
  setOnline: (online) => {
    if (get().online === online) return
    set({ online, since: Date.now() })
  },
}))

/** Resolve once the network is back (immediately if already online). */
export function waitForOnline(signal: AbortSignal): Promise<void> {
  if (useNetworkStore.getState().online) return Promise.resolve()
  return new Promise((resolve, reject) => {
    const unsub = useNetworkStore.subscribe((s) => {
      if (s.online) {
        unsub()
        resolve()
      }
    })
    signal.addEventListener("abort", () => {
      unsub()
      reject(new DOMException("aborted", "AbortError"))
    })
  })
}
