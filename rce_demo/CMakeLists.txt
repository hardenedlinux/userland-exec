# =============================================================================
# rce_demo/CMakeLists.txt
#
# Builds the two binaries used in the ROP → userland-exec noexec bypass rce_demo:
#
#   victim_server  —  intentionally vulnerable TCP server (the target)
#   payload        —  ELF binary deployed to the noexec-mounted partition
#
# WARNING: victim_server is compiled with all security mitigations DISABLED.
#          This is intentional — it is a controlled rce_demo target only.
# =============================================================================

# ── victim_server ─────────────────────────────────────────────────────────────
#
# Intentionally insecure flags:
#   -O0                 predictable stack layout (no compiler reordering)
#   -fno-stack-protector  no stack canary → pure stack BOF target
#   -g                  DWARF symbols → exploit.py can locate symbols via nm(1)
#   -w                  suppress warnings (code is intentionally unsafe)
#
# Link flags:
#   -no-pie             disable PIE → fixed .text / .data virtual addresses
#   -Wl,-z,norelro      disable RELRO → fully writable GOT (belt-and-suspenders)

add_executable(victim_server victim_server.c)

target_include_directories(victim_server PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(victim_server PRIVATE
    userland-exec
)

target_compile_options(victim_server PRIVATE
    -O0
    -fno-stack-protector
    -g
    -w
)

set_target_properties(victim_server PROPERTIES
    LINK_FLAGS "-no-pie -Wl,-z,norelro -Wl,-z,execstack"
)

# ── payload ───────────────────────────────────────────────────────────────────
#
# A normal, dynamically-linked binary that proves execution succeeded from
# inside the noexec-mounted partition.  No special flags needed.

add_executable(payload payload.c)

target_compile_options(payload PRIVATE
    -O2
    -w
)
