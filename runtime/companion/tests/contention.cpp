#include "contention.h"

#include <mutex>
namespace {
struct Hook {
  void (*callback)(void*) = nullptr;
  void* context = nullptr;
};
Hook& hook() {
  static thread_local Hook value;
  return value;
}
void acquired(int status) {
  if (status == 0 && hook().callback != nullptr) {
    const auto callback = hook().callback;
    void* context = hook().context;
    hook().callback = nullptr;
    hook().context = nullptr;
    callback(context);
  }
}
}  // namespace
extern "C" int real_mutex_try(std::mutex::native_handle_type mutex) asm("__real_pthread_mutex_trylock");
extern "C" int wrapped_mutex_try(std::mutex::native_handle_type mutex) asm("__wrap_pthread_mutex_trylock");
extern "C" int real_mutex_lock(std::mutex::native_handle_type mutex) asm("__real_pthread_mutex_lock");
extern "C" int wrapped_mutex_lock(std::mutex::native_handle_type mutex) asm("__wrap_pthread_mutex_lock");
int wrapped_mutex_try(std::mutex::native_handle_type mutex) {
  const int status = real_mutex_try(mutex);
  acquired(status);
  return status;
}
int wrapped_mutex_lock(std::mutex::native_handle_type mutex) {
  const int status = real_mutex_lock(mutex);
  acquired(status);
  return status;
}
void fixture::after_next_mutex(void (*callback)(void*), void* context) {
  hook().callback = callback;
  hook().context = context;
}
