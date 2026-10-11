/// Tests for the HTTP request builder.

#include "rasp/util/http.h"

#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>

namespace rasp::http {
namespace {

TEST(Http, postRequest_whenGivenAHostPathAndBody_writesTheExactRequest) {
  EXPECT_EQ(post_request("adr.example.com", "/apis/graphql", R"({"query":"x"})"),
            std::optional<std::string>{"POST /apis/graphql HTTP/1.1\r\n"
                                       "Host: adr.example.com\r\n"
                                       "Content-Type: application/json\r\n"
                                       "Content-Length: 13\r\n"
                                       "Connection: close\r\n"
                                       "\r\n"
                                       R"({"query":"x"})"});
}

TEST(Http, postRequest_whenTheBodyIsEmpty_sendsAZeroContentLength) {
  EXPECT_EQ(post_request("adr.example.com", "/", ""), std::optional<std::string>{"POST / HTTP/1.1\r\n"
                                                                                 "Host: adr.example.com\r\n"
                                                                                 "Content-Type: application/json\r\n"
                                                                                 "Content-Length: 0\r\n"
                                                                                 "Connection: close\r\n"
                                                                                 "\r\n"});
}

TEST(Http, postRequest_whenTheBodyHasMultiByteCharacters_countsBytesNotCharacters) {
  const std::optional<std::string> request = post_request("adr.example.com", "/", "caf\xc3\xa9");

  ASSERT_TRUE(request.has_value());
  EXPECT_NE(request->find("Content-Length: 5\r\n"), std::string::npos);
}

TEST(Http, postRequest_whenTheBodyHasNulAndLineBreaks_sendsItUnchanged) {
  const std::string_view body{"a\0\r\nb", 5};

  EXPECT_EQ(post_request("adr.example.com", "/", body),
            std::optional<std::string>{std::string{"POST / HTTP/1.1\r\n"
                                                   "Host: adr.example.com\r\n"
                                                   "Content-Type: application/json\r\n"
                                                   "Content-Length: 5\r\n"
                                                   "Connection: close\r\n"
                                                   "\r\n"} +
                                       std::string{body}});
}

TEST(Http, postRequest_whenTheHostAndPathUseTheFirstAndLastVisibleCharacters_acceptsThem) {
  const std::optional<std::string> request = post_request("!adr~", "/!~", "{}");

  ASSERT_TRUE(request.has_value());
  EXPECT_TRUE(request->starts_with("POST /!~ HTTP/1.1\r\nHost: !adr~\r\n"));
}

TEST(Http, postRequest_whenTheHostIsUnsafe_returnsNothing) {
  for (const std::string_view host : {
           "",
           "adr.example.com\r\nX-Injected: 1",
           "adr example.com",
           "adr.example.com\n",
           "adr\x7f.example.com",
           "caf\xc3\xa9.example.com",
       }) {
    EXPECT_EQ(post_request(host, "/apis/graphql", "{}"), std::nullopt) << host;
  }
}

TEST(Http, postRequest_whenThePathIsUnsafe_returnsNothing) {
  for (const std::string_view path : {
           "",
           "apis/graphql",
           "/apis graphql",
           "/apis/graphql\r\nX-Injected: 1",
           "/\t",
           "/\x7f",
           "/caf\xc3\xa9",
       }) {
    EXPECT_EQ(post_request("adr.example.com", path, "{}"), std::nullopt) << path;
  }
}

}  // namespace
}  // namespace rasp::http
