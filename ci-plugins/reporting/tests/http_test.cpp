/// Tests for HTTP/1.1: the parts of an endpoint URL, the request of a post, and the status line of an answer.

#include "http.h"

#include <gtest/gtest.h>
#include <optional>
#include <string>

namespace rasp::plugins::reporting {
namespace {

TEST(Http, parseEndpoint_whenHttpsWithPath_givesTlsAndPort443) {
  const std::optional<Endpoint> endpoint = parse_endpoint("https://adr.ostorlab.app/apis/graphql");

  ASSERT_TRUE(endpoint.has_value());
  EXPECT_TRUE(endpoint->tls);
  EXPECT_EQ(endpoint->host, "adr.ostorlab.app");
  EXPECT_EQ(endpoint->port, "443");
  EXPECT_EQ(endpoint->authority, "adr.ostorlab.app");
  EXPECT_EQ(endpoint->target, "/apis/graphql");
}

TEST(Http, parseEndpoint_whenHttpWithPort_givesThePortAndKeepsItInTheAuthority) {
  const std::optional<Endpoint> endpoint = parse_endpoint("http://10.0.2.2:8000/apis/graphql");

  ASSERT_TRUE(endpoint.has_value());
  EXPECT_FALSE(endpoint->tls);
  EXPECT_EQ(endpoint->host, "10.0.2.2");
  EXPECT_EQ(endpoint->port, "8000");
  EXPECT_EQ(endpoint->authority, "10.0.2.2:8000");
}

TEST(Http, parseEndpoint_whenNoPath_givesTheRootTarget) {
  const std::optional<Endpoint> endpoint = parse_endpoint("http://example.com");

  ASSERT_TRUE(endpoint.has_value());
  EXPECT_EQ(endpoint->port, "80");
  EXPECT_EQ(endpoint->target, "/");
}

TEST(Http, parseEndpoint_whenQueryAndFragment_keepsTheQueryAndDropsTheFragment) {
  const std::optional<Endpoint> with_path = parse_endpoint("https://example.com/rasp?a=1#top");
  const std::optional<Endpoint> without_path = parse_endpoint("https://example.com?a=1");

  ASSERT_TRUE(with_path.has_value());
  ASSERT_TRUE(without_path.has_value());
  EXPECT_EQ(with_path->target, "/rasp?a=1");
  EXPECT_EQ(without_path->target, "/?a=1");
}

TEST(Http, parseEndpoint_whenNotAnHttpUrl_givesNothing) {
  for (const char* url : {
           "ftp://example.com",
           "https://",
           "https:///rasp",
           "https://example.com:",
           "https://example.com:0",
           "https://example.com:65536",
           "https://example.com:8a",
           "https://a:b:c",
       }) {
    EXPECT_FALSE(parse_endpoint(url).has_value()) << url;
  }
}

TEST(Http, makeRequest_whenGivenABody_postsItWithItsLengthAndClosesTheConnection) {
  const Endpoint endpoint{
      .tls = true,
      .host = "example.com",
      .port = "443",
      .authority = "example.com",
      .target = "/rasp",
  };

  const std::string request = make_request(endpoint, R"({"a":1})");

  EXPECT_EQ(request,
            "POST /rasp HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 7\r\n"
            "Connection: close\r\n\r\n{\"a\":1}");
}

TEST(Http, parseStatus_whenAStatusLine_givesTheCode) {
  EXPECT_EQ(parse_status("HTTP/1.1 200 OK"), 200);
  EXPECT_EQ(parse_status("HTTP/1.0 404 Not Found"), 404);
  EXPECT_EQ(parse_status("HTTP/1.1 204"), 204);
}

TEST(Http, parseStatus_whenNotAStatusLine_givesNothing) {
  for (const char* line : {
           "",
           "HTTP/2 200 OK",
           "HTTP/1.1 20 OK",
           "HTTP/1.1 2000 OK",
           "HTTP/1.1 2x0 OK",
           "HTTP/1.1  200 OK",
           "http/1.1 200 OK",
           "HTTP/1.x 200 OK",
       }) {
    EXPECT_FALSE(parse_status(line).has_value()) << line;
  }
}

}  // namespace
}  // namespace rasp::plugins::reporting
