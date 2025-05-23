

#ifdef __cplusplus
extern "C" {
#endif

struct nielsen_bindings_decoder_s
{
    int pid;
    int channelCount;
    int silentMode;

    struct {
        void *api;
        void *params;
        void *callback;
    } channels[16];
};

struct nielsen_bindings_decoder_s *nielsen_bindings_alloc(int pid, int channelCount);

int nielsen_bindings_write_plane(struct nielsen_bindings_decoder_s *ctx, int channelnr, uint8_t *sample, int lengthBytes);

void nielsen_bindings_write_silent(struct nielsen_bindings_decoder_s *ctx, int tf);

void nielsen_bindings_free(struct nielsen_bindings_decoder_s *ctx);

#ifdef __cplusplus
};
#endif
