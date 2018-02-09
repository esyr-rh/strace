/**
 * Stub for arch-specific checks that should be performad during the
 * initialisation.  Architectures can define their own function in
 * linux/<ARCH>/arch_peculiarities.c, which then will be included in strace.c
 * and called from the init() routine.
 */
static void
test_arch_peculiarities(void)
{
}
