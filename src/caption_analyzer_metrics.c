/* Copyright LiveTimeNet, Inc. 2025. All Rights Reserved. */

#include "caption_analyzer_public.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>

// Metrics

// Simple HTTP response writer
static void write_metrics(struct prometheus_exporter_s *prom_ctx, int client_fd)
{
	struct tool_ctx_s *ctx = container_of(prom_ctx, struct tool_ctx_s, prom_ctx);

#define BUFFER_SIZE 8192
    char response[BUFFER_SIZE];

	/*
	streams_detected_total 2
	streams_monitoring_teletext 1
	streams_monitoring_cea608 1
	lang_pid_0xNNNN_eng_found = %d
	lang_pid_0xNNNN_eng_missing = %d
	lang_pid_0xNNNN_eng_processed = %d
	lang_pid_0xNNNN_eng_accuracy_pct = %f
	pid_0xNNNN_syntax_errors = %d
	*/

    snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain; version=0.0.4\r\n"
        "Connection: close\r\n"
        "\r\n");

	int total_ttx = 0, total_608 = 0;
	for (int i = 0; i < ctx->totalOrderedPids; i++) {
		struct input_pid_s *p = ctx->pidsOrdered[i];
		if (p->payloadType == PT_OP47)
			total_ttx++;
		else
		if (p->payloadType == PT_VIDEO)
			total_608++;
	}	

	snprintf(response + strlen(response), sizeof(response),
		"# HELP streams_detected_total Number of caption payload pids this probe has detected.\n"
		"# TYPE streams_detected_total counter\n"
		"streams_detected_total %d\n",
		ctx->totalOrderedPids);

	snprintf(response + strlen(response), sizeof(response),
		"# HELP streams_monitoring_teletext Number of teletext payload pids this probe is monitoring.\n"
		"# TYPE streams_monitoring_teletext counter\n"
		"streams_monitoring_teletext %d\n",
		total_ttx);

	snprintf(response + strlen(response), sizeof(response),
		"# HELP streams_monitoring_cea608 Number of CEA-608/708 payload pids this probe is monitoring.\n"
		"# TYPE streams_monitoring_cea608 counter\n"
		"streams_monitoring_cea608 %d\n",
		total_608);

	/* Feed any PES extractors */
	for (int i = 0; i < ctx->totalOrderedPids; i++) {
		struct input_pid_s *p = ctx->pidsOrdered[i];

		snprintf(response + strlen(response), sizeof(response),
			"# HELP pid_0x%x_syntax_errors Number of parsing issues found in stream.\n"
			"# TYPE pid_0x%x_syntax_errors counter\n"
			"pid_0x%04x_syntax_errors %" PRIu64 "\n",
			p->pid,
			p->pid,
			p->pid,
			p->syntaxError);

		for (int j = 0; j < LANG_MAX_DEFINED; j++) {
			struct langdict_stats_s *ls = &p->stats[j];

			if (ls->lang == LANG_UNDEFINED)
				continue;

			const char *name = langdict_3letter_name(ls->lang);

			snprintf(response + strlen(response), sizeof(response),
				"# HELP lang_pid_0x%04x_%s_found Number of valid words found in stream.\n"
				"# TYPE lang_pid_0x%04x_%s_found counter\n"
				"lang_pid_0x%04x_%s_found %" PRIu64 "\n",
				p->pid, name,
				p->pid, name,
				p->pid, name,
				ls->found);

			snprintf(response + strlen(response), sizeof(response),
				"# HELP lang_pid_0x%04x_%s_missing Number of invalid words found in stream.\n"
				"# TYPE lang_pid_0x%04x_%s_missing counter\n"
				"lang_pid_0x%04x_%s_missing %" PRIu64 "\n",
				p->pid, name, p->pid, name, p->pid, name,
				ls->missing);

			snprintf(response + strlen(response), sizeof(response),
				"# HELP lang_pid_0x%04x_%s_processed Number of tokens found in stream, we attempted to process.\n"
				"# TYPE lang_pid_0x%04x_%s_processed counter\n"
				"lang_pid_0x%04x_%s_processed %" PRIu64 "\n",
				p->pid, name, p->pid, name, p->pid, name,
				ls->processed);

			snprintf(response + strlen(response), sizeof(response),
				"# HELP lang_pid_0x%04x_%s_accuracy_pct Level of accuracy for a given dictionary vs stream payload.\n"
				"# TYPE lang_pid_0x%04x_%s_accuracy_pct counter\n"
				"lang_pid_0x%04x_%s_accuracy_pct %.1f\n",
				p->pid, name, p->pid, name, p->pid, name,
				ls->accuracypct);
		}
	}

	write(client_fd, response, strlen(response));
}

static void handle_client(struct prometheus_exporter_s *prom_ctx, int client_fd)
{
    char buffer[BUFFER_SIZE];
    read(client_fd, buffer, sizeof(buffer) - 1);

    // Simple HTTP route handling
    if (strstr(buffer, "GET /metrics") != NULL) {
        write_metrics(prom_ctx, client_fd);
    } else {
        const char *not_found = "HTTP/1.1 404 Not Found\r\n"
                                "Content-Length: 0\r\n"
                                "Connection: close\r\n\r\n";
        write(client_fd, not_found, strlen(not_found));
    }

    close(client_fd);
}

static int set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl(F_GETFL) failed");
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl(F_SETFL) failed");
        return -1;
    }
    return 0;
}

void caption_analyzer_metrics_free(struct prometheus_exporter_s *prom_ctx)
{
	if (prom_ctx->inputPort > 0 && prom_ctx->serverfd > 0) {
		close(prom_ctx->serverfd);
		prom_ctx->serverfd = -1;
	}
}

int caption_analyzer_metrics_alloc(struct prometheus_exporter_s *prom_ctx)
{
    struct sockaddr_in server_addr;

	if (prom_ctx->inputPort == 0) {
		return 0; /* Don't use this facility */
	}

    // Create socket
    if ((prom_ctx->serverfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return -EINVAL;
    }

	// Set socket to non-blocking mode
    if (set_non_blocking(prom_ctx->serverfd) < 0) {
        close(prom_ctx->serverfd);
		return -EINVAL;
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(prom_ctx->inputPort);

	int opt = 1;
	if (setsockopt(prom_ctx->serverfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		perror("setsockopt failed");
		close(prom_ctx->serverfd);
		return -EINVAL;
	}

    // Bind socket
    if (bind(prom_ctx->serverfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(prom_ctx->serverfd);
        return -EINVAL;
    }

    // Listen for incoming connections
    if (listen(prom_ctx->serverfd, 10) < 0) {
        perror("Listen failed");
        close(prom_ctx->serverfd);
        return -EINVAL;
    }

    return 0;
}

void caption_analyzer_metrics_service(struct prometheus_exporter_s *prom_ctx)
{
	if (prom_ctx->serverfd < 0) {
		/* Service has shutdown */
		usleep(10 * 1000);
		return;
	}

	struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

	int client_fd = accept(prom_ctx->serverfd, (struct sockaddr *)&client_addr, &client_len);
	if (client_fd < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			/* The caller will block for a while, before asking again */
			return;
		} else {
			perror("Accept failed");
		}
	}

	handle_client(prom_ctx, client_fd);	
}
