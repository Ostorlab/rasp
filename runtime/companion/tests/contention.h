/// Test-only barrier after an actual pthread mutex acquisition; production state is never replaced.
#pragma once
namespace fixture {
/// The current test thread pauses once after its next successful actual mutex acquisition.
void after_next_mutex(void (*callback)(void*), void* context);
}  // namespace fixture
