/// HttpsTransport, the Android transport: sends each request to the ADR server over HTTPS, with Java's
/// HttpsURLConnection called through JNI.

#pragma once

#include <chrono>
#include <jni.h>
#include <string>
#include <string_view>

#include "rasp/reporting/transport.h"

namespace rasp::android {

/// Sends each request to the ADR server over HTTPS, with Java's javax.net.ssl.HttpsURLConnection called through JNI.
///
/// Each post opens a new connection to the server, writes one POST, waits for the start of the server's answer, and
/// closes the connection. The platform does TLS and checks the server's certificate and host name. Not thread-safe:
/// it calls Java through the JNIEnv of one thread, so only that thread may post.
class HttpsTransport final : public Transport {
 public:
  /// Creates a transport for one endpoint of the ADR server. It connects to nothing until the first post.
  ///
  /// @param env The JNI environment of the thread that posts. That thread must be attached to the JVM, and the
  /// transport must not live longer than the attachment.
  /// @param host The server's host name, such as adr.example.com. When it is empty or isn't made only of visible ASCII
  /// characters, every post returns without sending anything.
  /// @param path The path of the GraphQL endpoint on the server, such as /apis/graphql. When it doesn't start with a
  /// slash or isn't made only of visible ASCII characters, every post returns without sending anything.
  /// @param timeout The connect timeout and the read timeout Java uses for each post, at least 1 millisecond.
  HttpsTransport(JNIEnv* env, std::string host, std::string path, std::chrono::milliseconds timeout);

  /// Sends one request body to the server and waits for the start of its answer, then closes the connection.
  ///
  /// It blocks the calling thread until the start of the answer arrives or a step fails. The answer's status is read
  /// and the rest of the answer is discarded. A post that fails, for example with no network, a certificate the
  /// platform refuses, or an app without the INTERNET permission, returns quietly: nothing is reported and nothing
  /// is retried.
  ///
  /// The timeout given to the constructor bounds each step, not the whole post. Java applies the connect timeout to
  /// each address of the server it tries, and the read timeout to each wait for data. Neither covers the DNS lookup,
  /// which takes as long as the system's resolver takes. So one post can take longer than the timeout.
  ///
  /// @param body The JSON request body, as submit_event_request writes it.
  void post(std::string_view body) noexcept override;

 private:
  /// The JNI environment of the thread that posts.
  JNIEnv* env_;
  /// The server's host name.
  std::string host_;
  /// The path of the GraphQL endpoint.
  std::string path_;
  /// The connect timeout and the read timeout of each post.
  std::chrono::milliseconds timeout_;
};

}  // namespace rasp::android
