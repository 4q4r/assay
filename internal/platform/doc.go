// Package platform is the per-OS seam layer (PHASE-CROSSPLATFORM S0):
// every platform-conditional decision — default paths, executable magic,
// file locking, core binary names, process liveness/termination, page-cache
// drops — lives here as an explicit, table-driven function instead of
// scattered GOOS branches or unix-only syscalls in feature packages. Linux
// behavior is byte-identical to the pre-S0 code paths the tables replaced
// (the existing resolve goldens stay untouched and green — the DoD gate).
package platform
