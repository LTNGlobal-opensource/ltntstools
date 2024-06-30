#include "nic_monitor.h"
#include "base64.h"

#include <curl/curl.h>

/* Setup a socket so we can push UDP datagrams */
int json_initialize(struct tool_context_s *ctx)
{
	ctx->jsonSocket = socket(AF_INET, SOCK_DGRAM, 0);
	if (ctx->jsonSocket < 0) {
		return -1;
	}

	int n = 1048576;
	if (setsockopt(ctx->jsonSocket, SOL_SOCKET, SO_SNDBUF, &n, sizeof(n)) == -1) {
		close(ctx->jsonSocket);
		return -1;
	}

	memset(&ctx->jsonSin, 0, sizeof(ctx->jsonSin));

	ctx->jsonSin.sin_family = AF_INET;
	ctx->jsonSin.sin_port = htons(5008);
	ctx->jsonSin.sin_addr.s_addr = inet_addr("127.0.0.1");
	ctx->jsonSin.sin_addr.s_addr = INADDR_ANY;

	/* Non-blocking required */
	int fl = fcntl(ctx->jsonSocket, F_GETFL, 0);
	if (fcntl(ctx->jsonSocket, F_SETFL, fl | O_NONBLOCK) < 0) {
		close(ctx->jsonSocket);
		return -1;
	}

	return 0;
}

void json_free(struct tool_context_s *ctx)
{
	if (ctx->jsonSocket >= 0) {
		close(ctx->jsonSocket);
		ctx->jsonSocket = -1;
	}
}

struct json_item_s *json_item_alloc(struct tool_context_s *ctx, int lengthBytesMax)
{
	struct json_item_s *item = calloc(1, sizeof(*item));
	if (!item)
		return NULL;

	item->lengthBytesMax = lengthBytesMax;
	item->buf = calloc(1, item->lengthBytesMax);

	return item;
}

void json_item_free(struct tool_context_s *ctx, struct json_item_s *item)
{
	free(item->buf);
	free(item);
}

/* Send the item to a remote server. */
int json_item_post_socket(struct tool_context_s *ctx, struct json_item_s *item)
{
	printf("posting json: '%s'\n", item->buf);

	if (ctx->jsonSocket < 0) {
		if (json_initialize(ctx) < 0)
			return -1;
	}

	size_t input_size = item->lengthBytes;
    char * encoded_data = base64_encode((const unsigned char *)item->buf, input_size, &input_size);
	printf("base64 = %s\n", encoded_data);

#if 0
	printf("sendto sending %d bytes skt %d\n", (int)input_size, ctx->jsonSocket);
#endif
	size_t v = sendto(ctx->jsonSocket, encoded_data, input_size, 0, (struct sockaddr *)&ctx->jsonSin, sizeof(ctx->jsonSin));
	if (v != input_size) {
		fprintf(stderr, "sendto error %lu\n", v);
		return -1;
	}
	return 0; /* Success */	
}

/* Demo code.
 * Send the item to a remote web server.
 */
int json_item_post_http(struct tool_context_s *ctx, struct json_item_s *item)
{
	int ret = -1;

#if 1
	printf("posting html json:\n%s\n", item->buf);
	return 0; /* Success */
#endif
//	return 0; /* Success */

#if 0
	size_t input_size = item->lengthBytes;
	char * encoded_data = base64_encode((const unsigned char *)item->buf, input_size, &input_size);
	printf("base64 = %s\n", encoded_data);
#endif

#if 0
	curl_global_init(CURL_GLOBAL_ALL);

	CURL *curl = curl_easy_init();
	if (!curl)
		return ret;

	struct curl_slist *headers = NULL;
	headers = curl_slist_append(headers, "Accept: application/json");
	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "charset: utf-8");

	//curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:13300/nicmonitor/01");
	curl_easy_setopt(curl, CURLOPT_URL, ctx->json_http_url);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, item->buf);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, item->lengthBytes);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcrp/0.1");
//	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	CURLcode res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
	} else {
		ret = 0; /* Success */
	}
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	curl_global_cleanup();

	return ret;
#endif

	return ret;	
}

/* Peek the list, don't remove it because our post may fail, and I don't want to
 * push this back on the head of the queue.
 * Assume we'll fail on our post.
 */
struct json_item_s *json_queue_peek(struct tool_context_s *ctx)
{
	struct json_item_s *item = NULL;

	pthread_mutex_lock(&ctx->lockJSONPost);
	while (!xorg_list_is_empty(&ctx->listJSONPost)) {
		item = xorg_list_first_entry(&ctx->listJSONPost, struct json_item_s, list);
		break;
	}
	pthread_mutex_unlock(&ctx->lockJSONPost);

	return item;
}

/* Pop something off the list, called will delete the returned object lifespan. */
struct json_item_s *json_queue_pop(struct tool_context_s *ctx)
{
	struct json_item_s *item = NULL;

	pthread_mutex_lock(&ctx->lockJSONPost);
	while (!xorg_list_is_empty(&ctx->listJSONPost)) {
		item = xorg_list_first_entry(&ctx->listJSONPost, struct json_item_s, list);
		xorg_list_del(&item->list);
		break;
	}
	pthread_mutex_unlock(&ctx->lockJSONPost);

	return item;
}

/* Append to list */
int json_queue_push(struct tool_context_s *ctx, struct json_item_s *item)
{
	pthread_mutex_lock(&ctx->lockJSONPost);
	xorg_list_append(&item->list, &ctx->listJSONPost);
	pthread_mutex_unlock(&ctx->lockJSONPost);

	return 0; /* Success */
}